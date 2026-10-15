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

// the bytes after `key` (a CBOR text string) when a 32-byte byte string follows it
bytes find_bstr32_after(const bytes &haystack, const std::string &key) {
	bytes needle;
	append_tstr(needle, key);
	needle.insert(needle.end(), {0x58, 0x20});
	auto at = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
	if (at == haystack.end() || haystack.end() - at < static_cast<long>(needle.size() + 32)) {
		return {};
	}
	return bytes(at + needle.size(), at + needle.size() + 32);
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

	bytes make_credential(const bytes &extensions) {
		bytes r{0xa5, 0x01, 0x58, 0x20};
		r.insert(r.end(), 32, 0x11);
		r.insert(r.end(), {0x02, 0xa1, 0x62, 'i', 'd', 0x63, 'a', '.', 'b'});
		r.insert(r.end(), {0x03, 0xa1, 0x62, 'i', 'd', 0x41, 0x01});
		r.insert(r.end(), {0x04, 0x81, 0xa2, 0x63, 'a', 'l', 'g', 0x26, 0x64, 't', 'y', 'p', 'e',
			0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
		r.push_back(0x06);
		r.insert(r.end(), extensions.begin(), extensions.end());
		request(CTAP_CMD_MAKE_CREDENTIAL, r);
		return response_bytes();
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

} // namespace
