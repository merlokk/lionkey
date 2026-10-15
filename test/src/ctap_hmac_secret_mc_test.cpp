#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
#include <string>
#include <vector>
extern "C" {
#include <ctap.h>
#include <ctap_crypto_software.h>
#include <ctap_memory_storage.h>
#include <ctap_test.h>
#include <aes.h>
#include <hmac.h>
#include <sha256.h>
#include <uECC.h>
}
namespace {

using bytes = std::vector<uint8_t>;

// the platform's key-agreement key (the same as in ctap_client_pin_test.cpp)
constexpr auto platform_private_key = hex::bytes<
	"b6a7164827e98933906aa13b90dd8bf6a15989a3419d90ecc1cde95a80aefb6c"
>();
constexpr auto platform_public_x = hex::bytes<
	"bcfd95db7be64d2dc19d450b87635f9dfc5a4a7c872c3a66cc98e2f724799095"
>();
constexpr auto platform_public_y = hex::bytes<
	"d55c3641e99a6ca1ebe9bc6600df3de0f2e3be334359c7422bff873f341f379b"
>();

// micro-ecc's (LionKey fork) random numbers for the ECDH blinding: any will do in a test
int test_rng(void *, uint8_t *dest, unsigned size) {
	for (unsigned i = 0; i < size; ++i) {
		dest[i] = static_cast<uint8_t>(0x5a ^ (i * 31));
	}
	return 1;
}

bytes sha256(const uint8_t *data, size_t size) {
	const hash_alg_t *const alg = &hash_alg_sha256;
	std::vector<uint8_t> ctx(alg->ctx_size);
	bytes out(32);
	alg->init(ctx.data());
	alg->update(ctx.data(), data, size);
	alg->final(ctx.data(), out.data());
	return out;
}

bytes hmac_sha256(const bytes &key, const bytes &data) {
	const hash_alg_t *const alg = &hash_alg_sha256;
	std::vector<uint8_t> hash_ctx(alg->ctx_size);
	std::vector<uint8_t> ctx(hmac_get_context_size(alg));
	bytes out(32);
	hmac_init(ctx.data(), alg, hash_ctx.data(), key.data(), key.size());
	hmac_update(ctx.data(), data.data(), data.size());
	hmac_final(ctx.data(), out.data());
	return out;
}

// PIN/UV auth protocol one: AES-256-CBC with a zero IV
bytes aes_cbc(const bytes &key, bytes data, bool encrypt) {
	AES_ctx ctx;
	const uint8_t iv[16] = {};
	AES_init_ctx_iv(&ctx, key.data(), iv);
	if (encrypt) {
		AES_CBC_encrypt_buffer(&ctx, data.data(), data.size());
	} else {
		AES_CBC_decrypt_buffer(&ctx, data.data(), data.size());
	}
	return data;
}

void append_bstr(bytes &out, const bytes &data) {
	if (data.size() < 24) {
		out.push_back(static_cast<uint8_t>(0x40 | data.size()));
	} else {
		out.push_back(0x58);
		out.push_back(static_cast<uint8_t>(data.size()));
	}
	out.insert(out.end(), data.begin(), data.end());
}

void append_tstr(bytes &out, const std::string &text) {
	out.push_back(static_cast<uint8_t>(0x60 | text.size())); // < 24 bytes
	out.insert(out.end(), text.begin(), text.end());
}

// the bytes after `key` (a CBOR text string) when a byte string of `size` (24 to 255) follows it
bytes find_bstr_after(const bytes &haystack, const std::string &key, size_t size) {
	bytes needle;
	append_tstr(needle, key);
	needle.insert(needle.end(), {0x58, static_cast<uint8_t>(size)});
	auto at = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
	if (at == haystack.end() || haystack.end() - at < static_cast<long>(needle.size() + size)) {
		return {};
	}
	return bytes(at + static_cast<long>(needle.size()), at + static_cast<long>(needle.size() + size));
}

// the bytes after `key` (a CBOR text string) when a 32-byte byte string follows it
bytes find_bstr32_after(const bytes &haystack, const std::string &key) {
	return find_bstr_after(haystack, key, 32);
}

// the position of `key` (a CBOR text string) in `haystack`, -1 when absent
long find_tstr(const bytes &haystack, const std::string &key) {
	bytes needle;
	append_tstr(needle, key);
	auto at = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
	return at == haystack.end() ? -1 : at - haystack.begin();
}

// the credential ID in a makeCredential response {1: fmt, 2: authData, ...}: authData (after rpIdHash,
// flags, signCount, aaguid, length) is 02 58 <len> (under 256 bytes) or 02 59 <len 2>
bytes credential_id_of(const bytes &mc) {
	const bytes short_label{0x02, 0x58};
	const bytes long_label{0x02, 0x59};
	auto ad = std::search(mc.begin(), mc.end(), short_label.begin(), short_label.end());
	long header = 3;
	if (ad == mc.end()) {
		ad = std::search(mc.begin(), mc.end(), long_label.begin(), long_label.end());
		header = 4;
	}
	if (ad == mc.end() || mc.end() - ad < header + 55 + 32) {
		ADD_FAILURE() << "no authData";
		return {};
	}
	const auto auth_data = ad + header;
	return bytes(auth_data + 55, auth_data + 55 + 32);
}

class CtapHmacSecretMcTest : public testing::Test {
protected:
	uint8_t ctap_persistent_memory[16 * 1024]{};
	uint8_t ctap_response_buffer[CTAP_RESPONSE_BUFFER_SIZE]{};
	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ctap_memory_storage_context_t storage_ctx{
		.memory_size = sizeof(ctap_persistent_memory),
		.memory = ctap_persistent_memory,
	};
	const ctap_storage_t storage = CTAP_MEMORY_STORAGE_CONST_INIT(&storage_ctx);
	ctap_state_t ctap = CTAP_STATE_CONST_INIT(&crypto, &storage);
	ctap_response_t response{
		.data_max_size = sizeof(ctap_response_buffer),
		.data = ctap_response_buffer,
	};
	uint8_t status{};
	bytes shared_secret;

	CtapHmacSecretMcTest() {
		test_reset_user_presence();
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	void request(uint8_t cmd, const bytes &params) {
		status = ctap_request(&ctap, cmd, params.size(), params.data(), &response);
	}

	bytes response_bytes() const {
		return bytes(response.data, response.data + response.length);
	}

	// clientPIN getKeyAgreement (protocol one), then the shared secret SHA-256(ECDH x)
	void agree() {
		request(CTAP_CMD_CLIENT_PIN, {0xa2, 0x01, 0x01, 0x02, 0x02});
		ASSERT_EQ(status, CTAP2_OK);
		const bytes r = response_bytes();
		const bytes x_label{0x21, 0x58, 0x20};
		const bytes y_label{0x22, 0x58, 0x20};
		auto x = std::search(r.begin(), r.end(), x_label.begin(), x_label.end());
		auto y = std::search(r.begin(), r.end(), y_label.begin(), y_label.end());
		ASSERT_NE(x, r.end());
		ASSERT_NE(y, r.end());
		uint8_t authenticator_public[64];
		std::copy(x + 3, x + 35, authenticator_public);
		std::copy(y + 3, y + 35, authenticator_public + 32);
		uint8_t z[32];
		ASSERT_EQ(uECC_shared_secret(authenticator_public, platform_private_key.data(), z, uECC_secp256r1(), test_rng, nullptr), 1);
		shared_secret = sha256(z, sizeof(z));
	}

	// {1: platform key, 2: saltEnc, 3: saltAuth, 4: 1}
	bytes hmac_secret_input(const bytes &salt) {
		const bytes salt_enc = aes_cbc(shared_secret, salt, true);
		const bytes salt_auth_full = hmac_sha256(shared_secret, salt_enc);
		const bytes salt_auth(salt_auth_full.begin(), salt_auth_full.begin() + 16);
		bytes m{0xa4, 0x01, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20};
		m.insert(m.end(), platform_public_x.begin(), platform_public_x.end());
		m.insert(m.end(), {0x22, 0x58, 0x20});
		m.insert(m.end(), platform_public_y.begin(), platform_public_y.end());
		m.push_back(0x02);
		append_bstr(m, salt_enc);
		m.push_back(0x03);
		append_bstr(m, salt_auth);
		m.insert(m.end(), {0x04, 0x01});
		return m;
	}

	// clientDataHash 32 x 0x11; `token` not empty: pinUvAuthParam (protocol one) with it
	bytes make_credential(const bytes &extensions, const bytes &token = {}) {
		bytes r{static_cast<uint8_t>(token.empty() ? 0xa5 : 0xa7), 0x01, 0x58, 0x20};
		r.insert(r.end(), 32, 0x11);
		r.insert(r.end(), {0x02, 0xa1, 0x62, 'i', 'd', 0x63, 'a', '.', 'b'});
		r.insert(r.end(), {0x03, 0xa1, 0x62, 'i', 'd', 0x41, 0x01});
		r.insert(r.end(), {0x04, 0x81, 0xa2, 0x63, 'a', 'l', 'g', 0x26, 0x64, 't', 'y', 'p', 'e',
			0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
		r.push_back(0x06);
		r.insert(r.end(), extensions.begin(), extensions.end());
		if (!token.empty()) {
			const bytes mac = hmac_sha256(token, bytes(32, 0x11));
			r.push_back(0x08);
			append_bstr(r, bytes(mac.begin(), mac.begin() + 16));
			r.insert(r.end(), {0x09, 0x01});
		}
		request(CTAP_CMD_MAKE_CREDENTIAL, r);
		return response_bytes();
	}

	// {"hmac-secret": true, "hmac-secret-mc": `input`}
	static bytes hmac_secret_mc_extensions(const bytes &input) {
		bytes ext{0xa2};
		append_tstr(ext, "hmac-secret");
		ext.push_back(0xf5);
		append_tstr(ext, "hmac-secret-mc");
		ext.insert(ext.end(), input.begin(), input.end());
		return ext;
	}

	// getAssertion for "a.b" (clientDataHash 32 x 0x22) with {"hmac-secret": `input`};
	// `token` not empty: pinUvAuthParam (protocol one) with it
	bytes get_assertion(const bytes &credential_id, const bytes &input, const bytes &token = {}) {
		bytes ga{static_cast<uint8_t>(token.empty() ? 0xa4 : 0xa6), 0x01, 0x63, 'a', '.', 'b', 0x02, 0x58, 0x20};
		ga.insert(ga.end(), 32, 0x22);
		ga.insert(ga.end(), {0x03, 0x81, 0xa2, 0x62, 'i', 'd', 0x58, 0x20});
		ga.insert(ga.end(), credential_id.begin(), credential_id.end());
		ga.insert(ga.end(), {0x64, 't', 'y', 'p', 'e', 0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
		ga.insert(ga.end(), {0x04, 0xa1});
		append_tstr(ga, "hmac-secret");
		ga.insert(ga.end(), input.begin(), input.end());
		if (!token.empty()) {
			const bytes mac = hmac_sha256(token, bytes(32, 0x22));
			ga.push_back(0x06);
			append_bstr(ga, bytes(mac.begin(), mac.begin() + 16));
			ga.insert(ga.end(), {0x07, 0x01});
		}
		request(CTAP_CMD_GET_ASSERTION, ga);
		return response_bytes();
	}

	// a PIN, set directly: CurrentStoredPIN = LEFT(SHA-256(PIN), 16)
	void set_pin(const std::string &pin) {
		const bytes hash = sha256(reinterpret_cast<const uint8_t *>(pin.data()), pin.size());
		std::copy(hash.begin(), hash.begin() + 16, ctap.pin_state.pin_hash);
		ctap.pin_state.pin_code_point_length = static_cast<uint8_t>(pin.size());
		ctap.pin_state.is_pin_set = 1u;
		ctap_update_pin_persistent_state(&ctap);
	}

	// clientPIN getPinUvAuthTokenUsingPinWithPermissions (protocol one, rpId "a.b"): the decrypted token
	bytes pin_token(const std::string &pin, uint8_t permissions) {
		agree();
		const bytes pin_hash = sha256(reinterpret_cast<const uint8_t *>(pin.data()), pin.size());
		const bytes pin_hash_enc = aes_cbc(shared_secret, bytes(pin_hash.begin(), pin_hash.begin() + 16), true);
		bytes r{0xa6, 0x01, 0x01, 0x02, 0x09, 0x03, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20};
		r.insert(r.end(), platform_public_x.begin(), platform_public_x.end());
		r.insert(r.end(), {0x22, 0x58, 0x20});
		r.insert(r.end(), platform_public_y.begin(), platform_public_y.end());
		r.push_back(0x06);
		append_bstr(r, pin_hash_enc);
		r.insert(r.end(), {0x09, permissions}); // < 24
		r.insert(r.end(), {0x0a, 0x63, 'a', '.', 'b'});
		request(CTAP_CMD_CLIENT_PIN, r);
		if (status != CTAP2_OK || response.length != 4u + 32u) {
			ADD_FAILURE() << "no pinUvAuthToken: status " << static_cast<int>(status);
			return {};
		}
		// {2: h'<32>'}: a1 02 58 20
		return aes_cbc(shared_secret, bytes(response.data + 4, response.data + 4 + 32), false);
	}
};

TEST_F(CtapHmacSecretMcTest, GetInfoListsIt) {
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	const bytes r = response_bytes();
	const std::string id = "hmac-secret-mc";
	bytes needle;
	append_tstr(needle, id);
	EXPECT_NE(std::search(r.begin(), r.end(), needle.begin(), needle.end()), r.end());
}

TEST_F(CtapHmacSecretMcTest, NeedsHmacSecret) {
	agree();
	const bytes salt(32, 0x5a);
	bytes ext{0xa1};
	append_tstr(ext, "hmac-secret-mc");
	const bytes input = hmac_secret_input(salt);
	ext.insert(ext.end(), input.begin(), input.end());
	make_credential(ext);
	EXPECT_EQ(status, CTAP2_ERR_MISSING_PARAMETER);
}

TEST_F(CtapHmacSecretMcTest, BadSaltAuth) {
	agree();
	const bytes salt(32, 0x5a);
	bytes input = hmac_secret_input(salt);
	input[input.size() - 3 - 1] ^= 0x01; // the last byte of saltAuth (before 04 01)
	bytes ext{0xa2};
	append_tstr(ext, "hmac-secret");
	ext.push_back(0xf5);
	append_tstr(ext, "hmac-secret-mc");
	ext.insert(ext.end(), input.begin(), input.end());
	make_credential(ext);
	EXPECT_EQ(status, CTAP2_ERR_PIN_AUTH_INVALID);
}

TEST_F(CtapHmacSecretMcTest, TheSameOutputAsGetAssertion) {
	agree();
	const bytes salt(32, 0x5a);
	bytes ext{0xa2};
	append_tstr(ext, "hmac-secret");
	ext.push_back(0xf5);
	append_tstr(ext, "hmac-secret-mc");
	const bytes input = hmac_secret_input(salt);
	ext.insert(ext.end(), input.begin(), input.end());
	const bytes mc = make_credential(ext);
	ASSERT_EQ(status, CTAP2_OK);
	const bytes mc_output_enc = find_bstr32_after(mc, "hmac-secret-mc");
	ASSERT_EQ(mc_output_enc.size(), 32u);
	const bytes mc_output = aes_cbc(shared_secret, mc_output_enc, false);

	// the credential ID: authData (after rpIdHash, flags, signCount, aaguid, length)
	// {1: "packed", 2: authData, ...}: 02 58 <len> (under 256 bytes) or 02 59 <len 2>
	const bytes short_label{0x02, 0x58};
	const bytes long_label{0x02, 0x59};
	auto ad = std::search(mc.begin(), mc.end(), short_label.begin(), short_label.end());
	size_t header = 3;
	if (ad == mc.end()) {
		ad = std::search(mc.begin(), mc.end(), long_label.begin(), long_label.end());
		header = 4;
	}
	ASSERT_NE(ad, mc.end());
	const auto auth_data = ad + static_cast<long>(header);
	const bytes credential_id(auth_data + 55, auth_data + 55 + 32);

	// getAssertion with hmac-secret and the same salt: the same output (uv false in both)
	bytes ga{0xa4, 0x01, 0x63, 'a', '.', 'b', 0x02, 0x58, 0x20};
	ga.insert(ga.end(), 32, 0x22);
	ga.insert(ga.end(), {0x03, 0x81, 0xa2, 0x62, 'i', 'd', 0x58, 0x20});
	ga.insert(ga.end(), credential_id.begin(), credential_id.end());
	ga.insert(ga.end(), {0x64, 't', 'y', 'p', 'e', 0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
	ga.insert(ga.end(), {0x04, 0xa1});
	append_tstr(ga, "hmac-secret");
	ga.insert(ga.end(), input.begin(), input.end());
	request(CTAP_CMD_GET_ASSERTION, ga);
	ASSERT_EQ(status, CTAP2_OK);
	const bytes ga_output_enc = find_bstr32_after(response_bytes(), "hmac-secret");
	ASSERT_EQ(ga_output_enc.size(), 32u);
	const bytes ga_output = aes_cbc(shared_secret, ga_output_enc, false);
	EXPECT_EQ(mc_output, ga_output);

	// and a different salt gives a different output
	const bytes other = hmac_secret_input(bytes(32, 0x5b));
	ga.erase(ga.end() - static_cast<long>(input.size()), ga.end());
	ga.insert(ga.end(), other.begin(), other.end());
	request(CTAP_CMD_GET_ASSERTION, ga);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_NE(aes_cbc(shared_secret, find_bstr32_after(response_bytes(), "hmac-secret"), false), mc_output);
}

TEST_F(CtapHmacSecretMcTest, HmacSecretFalseIsNotEnough) {
	agree();
	bytes ext{0xa2};
	append_tstr(ext, "hmac-secret");
	ext.push_back(0xf4);
	append_tstr(ext, "hmac-secret-mc");
	const bytes input = hmac_secret_input(bytes(32, 0x5a));
	ext.insert(ext.end(), input.begin(), input.end());
	make_credential(ext);
	EXPECT_EQ(status, CTAP2_ERR_MISSING_PARAMETER);
}

TEST_F(CtapHmacSecretMcTest, TwoSalts) {
	agree();
	bytes salts(32, 0x5a);
	salts.insert(salts.end(), 32, 0xa5);
	const bytes input = hmac_secret_input(salts);
	const bytes mc = make_credential(hmac_secret_mc_extensions(input));
	ASSERT_EQ(status, CTAP2_OK);
	const bytes mc_output_enc = find_bstr_after(mc, "hmac-secret-mc", 64);
	ASSERT_EQ(mc_output_enc.size(), 64u);
	const bytes mc_output = aes_cbc(shared_secret, mc_output_enc, false);
	EXPECT_NE(bytes(mc_output.begin(), mc_output.begin() + 32), bytes(mc_output.begin() + 32, mc_output.end()));
	const bytes credential_id = credential_id_of(mc);
	ASSERT_EQ(credential_id.size(), 32u);

	// getAssertion with the same two salts: the same two outputs
	const bytes ga_output_enc = find_bstr_after(get_assertion(credential_id, input), "hmac-secret", 64);
	ASSERT_EQ(status, CTAP2_OK);
	ASSERT_EQ(ga_output_enc.size(), 64u);
	EXPECT_EQ(aes_cbc(shared_secret, ga_output_enc, false), mc_output);
	// and each one alone
	for (size_t i = 0; i < 2; ++i) {
		const bytes salt(salts.begin() + static_cast<long>(32 * i), salts.begin() + static_cast<long>(32 * (i + 1)));
		const bytes one = find_bstr32_after(get_assertion(credential_id, hmac_secret_input(salt)), "hmac-secret");
		ASSERT_EQ(status, CTAP2_OK);
		ASSERT_EQ(one.size(), 32u);
		EXPECT_EQ(
			aes_cbc(shared_secret, one, false),
			bytes(mc_output.begin() + static_cast<long>(32 * i), mc_output.begin() + static_cast<long>(32 * (i + 1)))
		);
	}
}

TEST_F(CtapHmacSecretMcTest, WithUv) {
	const std::string pin = "4826";
	set_pin(pin);
	const bytes mc_token = pin_token(pin, CTAP_clientPIN_pinUvAuthToken_permission_mc);
	ASSERT_EQ(mc_token.size(), 32u);
	const bytes input = hmac_secret_input(bytes(32, 0x5a));
	const bytes mc = make_credential(hmac_secret_mc_extensions(input), mc_token);
	ASSERT_EQ(status, CTAP2_OK);
	const bytes credential_id = credential_id_of(mc);
	ASSERT_EQ(credential_id.size(), 32u);
	const bytes mc_output_enc = find_bstr32_after(mc, "hmac-secret-mc");
	ASSERT_EQ(mc_output_enc.size(), 32u);
	const bytes mc_output = aes_cbc(shared_secret, mc_output_enc, false);

	// getAssertion with UV: the same output (CredRandomWithUV)
	const bytes ga_token = pin_token(pin, CTAP_clientPIN_pinUvAuthToken_permission_ga);
	ASSERT_EQ(ga_token.size(), 32u);
	const bytes ga_uv = get_assertion(credential_id, input, ga_token);
	ASSERT_EQ(status, CTAP2_OK);
	const bytes ga_uv_output_enc = find_bstr32_after(ga_uv, "hmac-secret");
	ASSERT_EQ(ga_uv_output_enc.size(), 32u);
	EXPECT_EQ(aes_cbc(shared_secret, ga_uv_output_enc, false), mc_output);

	// without UV: another one (CredRandomWithoutUV)
	const bytes ga = get_assertion(credential_id, input);
	ASSERT_EQ(status, CTAP2_OK);
	const bytes ga_output_enc = find_bstr32_after(ga, "hmac-secret");
	ASSERT_EQ(ga_output_enc.size(), 32u);
	EXPECT_NE(aes_cbc(shared_secret, ga_output_enc, false), mc_output);
}

TEST_F(CtapHmacSecretMcTest, CanonicalOrderWithMinPinLength) {
	// authenticatorConfig setMinPINLength {1: 3, 2: {2: ["a.b"]}} (no PIN: no pinUvAuthParam)
	request(CTAP_CMD_CONFIG, {0xa2, 0x01, CTAP_authenticatorConfig_subCmd_setMinPINLength,
		0x02, 0xa1, 0x02, 0x81, 0x63, 'a', '.', 'b'});
	ASSERT_EQ(status, CTAP2_OK);
	agree();
	const bytes input = hmac_secret_input(bytes(32, 0x5a));
	bytes ext{0xa3};
	append_tstr(ext, "hmac-secret");
	ext.push_back(0xf5);
	append_tstr(ext, "minPinLength");
	ext.push_back(0xf5);
	append_tstr(ext, "hmac-secret-mc");
	ext.insert(ext.end(), input.begin(), input.end());
	const bytes mc = make_credential(ext);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	// the extensions map: {"hmac-secret": true, "minPinLength": n, "hmac-secret-mc": h'<32>'}
	// (CTAP2 canonical CBOR: shorter keys first)
	const long hmac_secret = find_tstr(mc, "hmac-secret");
	const long min_pin_length = find_tstr(mc, "minPinLength");
	const long hmac_secret_mc = find_tstr(mc, "hmac-secret-mc");
	ASSERT_GT(hmac_secret, 0);
	ASSERT_GT(min_pin_length, 0);
	ASSERT_GT(hmac_secret_mc, 0);
	EXPECT_EQ(mc[static_cast<size_t>(hmac_secret) - 1], 0xa3); // the map header
	EXPECT_EQ(mc[static_cast<size_t>(hmac_secret) + 12], 0xf5);
	EXPECT_EQ(min_pin_length, hmac_secret + 12 + 1);
	EXPECT_EQ(hmac_secret_mc, min_pin_length + 13 + 1); // minPinLength (< 24): one byte
	EXPECT_EQ(find_bstr32_after(mc, "hmac-secret-mc").size(), 32u);
}

} // namespace
