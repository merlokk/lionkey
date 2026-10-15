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

// the platform's built-in UV, replaced in this test (the core has weak defaults)
ctap_user_presence_result_t test_uv_result = CTAP_UP_RESULT_ALLOW;
unsigned test_uv_calls = 0;
unsigned test_uv_requests = 0;

ctap_user_presence_result_t ctap_perform_built_in_uv(void) {
	test_uv_calls++;
	return test_uv_result;
}

void ctap_on_built_in_uv_request(ctap_built_in_uv_t built_in_uv) {
	(void) built_in_uv;
	test_uv_requests++;
}
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

bytes sha256(const bytes &data) {
	const hash_alg_t *const alg = &hash_alg_sha256;
	std::vector<uint8_t> ctx(alg->ctx_size);
	bytes out(32);
	alg->init(ctx.data());
	alg->update(ctx.data(), data.data(), data.size());
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

// 9: permissions
void append_permissions(bytes &out, uint8_t permissions) {
	out.push_back(0x09);
	if (permissions < 24) {
		out.push_back(permissions);
	} else {
		out.insert(out.end(), {0x18, permissions});
	}
}

class CtapBuiltInUvTest : public testing::Test {
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

	CtapBuiltInUvTest() {
		test_reset_user_presence();
		test_uv_result = CTAP_UP_RESULT_ALLOW;
		test_uv_calls = 0;
		test_uv_requests = 0;
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	void request(uint8_t cmd, const bytes &params) {
		status = ctap_request(&ctap, cmd, params.size(), params.data(), &response);
	}

	bytes response_bytes() const {
		return bytes(response.data, response.data + response.length);
	}

	bool response_contains(const bytes &needle) const {
		const bytes r = response_bytes();
		return std::search(r.begin(), r.end(), needle.begin(), needle.end()) != r.end();
	}

	// 3: the platform's key-agreement key (COSE_Key)
	static bytes key_agreement() {
		bytes k{0x03, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20};
		k.insert(k.end(), platform_public_x.begin(), platform_public_x.end());
		k.insert(k.end(), {0x22, 0x58, 0x20});
		k.insert(k.end(), platform_public_y.begin(), platform_public_y.end());
		return k;
	}

	// clientPIN getPinUvAuthTokenUsingUvWithPermissions (protocol one)
	void uv_token(uint8_t permissions) {
		bytes r{0xa4, 0x01, 0x01, 0x02, 0x06};
		const bytes k = key_agreement();
		r.insert(r.end(), k.begin(), k.end());
		append_permissions(r, permissions);
		request(CTAP_CMD_CLIENT_PIN, r);
	}

	// a PIN, set directly: CurrentStoredPIN = LEFT(SHA-256(PIN), 16)
	void set_pin(const std::string &pin) {
		const bytes hash = sha256(bytes(pin.begin(), pin.end()));
		std::copy(hash.begin(), hash.begin() + 16, ctap.pin_state.pin_hash);
		ctap.pin_state.pin_code_point_length = static_cast<uint8_t>(pin.size());
		ctap.pin_state.is_pin_set = 1u;
		ctap_update_pin_persistent_state(&ctap);
	}

	// protocol one: SHA-256 of the ECDH x with the authenticator's key-agreement key
	bytes shared_secret() {
		request(CTAP_CMD_CLIENT_PIN, {0xa2, 0x01, 0x01, 0x02, 0x02});
		EXPECT_EQ(status, CTAP2_OK);
		const bytes r = response_bytes();
		const bytes x_label{0x21, 0x58, 0x20};
		const bytes y_label{0x22, 0x58, 0x20};
		auto x = std::search(r.begin(), r.end(), x_label.begin(), x_label.end());
		auto y = std::search(r.begin(), r.end(), y_label.begin(), y_label.end());
		if (x == r.end() || y == r.end()) {
			ADD_FAILURE() << "no key-agreement key";
			return {};
		}
		uint8_t authenticator_public[64];
		std::copy(x + 3, x + 35, authenticator_public);
		std::copy(y + 3, y + 35, authenticator_public + 32);
		uint8_t z[32];
		EXPECT_EQ(uECC_shared_secret(
			authenticator_public, platform_private_key.data(), z, uECC_secp256r1(), test_rng, nullptr
		), 1);
		return sha256(bytes(z, z + 32));
	}

	// the token of a successful {2: h'<32>'} response (a1 02 58 20 ...), decrypted
	bytes decrypt_token(const bytes &shared) const {
		EXPECT_EQ(response.length, 4u + 32u);
		if (response.length != 4u + 32u) {
			return {};
		}
		return aes_cbc(shared, bytes(response.data + 4, response.data + 4 + 32), false);
	}

	// clientPIN getPinUvAuthTokenUsingPinWithPermissions (protocol one): the decrypted token, or empty
	bytes pin_token(const std::string &pin, uint8_t permissions) {
		const bytes shared = shared_secret();
		const bytes pin_hash = sha256(bytes(pin.begin(), pin.end()));
		const bytes pin_hash_enc = aes_cbc(shared, bytes(pin_hash.begin(), pin_hash.begin() + 16), true);
		bytes r{0xa5, 0x01, 0x01, 0x02, 0x09};
		const bytes k = key_agreement();
		r.insert(r.end(), k.begin(), k.end());
		r.push_back(0x06);
		append_bstr(r, pin_hash_enc);
		append_permissions(r, permissions);
		request(CTAP_CMD_CLIENT_PIN, r);
		if (status != CTAP2_OK) {
			return {};
		}
		return decrypt_token(shared);
	}

	// credentialManagement getCredsMetadata with pinUvAuthParam = LEFT(HMAC(token, subCommand), 16)
	void get_creds_metadata(const bytes &token) {
		const uint8_t sub_command = CTAP_credentialManagement_subCmd_getCredsMetadata;
		const bytes mac = hmac_sha256(token, {sub_command});
		bytes r{0xa3, 0x01, sub_command, 0x03, 0x01, 0x04};
		append_bstr(r, bytes(mac.begin(), mac.begin() + 16));
		request(CTAP_CMD_CREDENTIAL_MANAGEMENT, r);
	}

	// getInfo member `key` (an unsigned integer) into `value`: false when absent
	bool get_info_uint(uint64_t key, uint64_t &value) {
		request(CTAP_CMD_GET_INFO, {});
		EXPECT_EQ(status, CTAP2_OK);
		CborParser parser;
		CborValue it;
		CborValue map;
		EXPECT_EQ(cbor_parser_init(response.data, response.length, 0, &parser, &it), CborNoError);
		EXPECT_EQ(cbor_value_enter_container(&it, &map), CborNoError);
		while (!cbor_value_at_end(&map)) {
			uint64_t k;
			EXPECT_EQ(cbor_value_get_uint64(&map, &k), CborNoError);
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
			if (k == key) {
				EXPECT_TRUE(cbor_value_is_unsigned_integer(&map));
				EXPECT_EQ(cbor_value_get_uint64(&map, &value), CborNoError);
				return true;
			}
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
		}
		return false;
	}

	// clientPIN getUVRetries: the count, -1 on an error
	int uv_retries() {
		request(CTAP_CMD_CLIENT_PIN, {0xa2, 0x01, 0x01, 0x02, 0x07});
		if (status != CTAP2_OK) {
			return -1;
		}
		// {5: n}
		const bytes r = response_bytes();
		EXPECT_GE(r.size(), 3u);
		EXPECT_EQ(r[0], 0xa1);
		EXPECT_EQ(r[1], 0x05);
		return r[2];
	}

	static bytes text(const std::string &s) {
		bytes b{static_cast<uint8_t>(0x60 | s.size())};
		b.insert(b.end(), s.begin(), s.end());
		return b;
	}
};

TEST_F(CtapBuiltInUvTest, NoneByDefault) {
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_FALSE(response_contains(text("uv")));
	EXPECT_EQ(uv_retries(), -1);
	EXPECT_EQ(status, CTAP2_ERR_INVALID_SUBCOMMAND);
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_INVALID_SUBCOMMAND);
	EXPECT_EQ(test_uv_requests, 0u);
}

TEST_F(CtapBuiltInUvTest, NotConfigured) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_NOT_CONFIGURED;
	ctap.uv_modality = 0x04;
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	bytes uv_false = text("uv");
	uv_false.push_back(0xf4);
	EXPECT_TRUE(response_contains(uv_false));
	EXPECT_TRUE(response_contains({0x12, 0x04})); // uvModality
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES);
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_NOT_ALLOWED);
	EXPECT_EQ(test_uv_requests, 1u); // told (the firmware logs it)
	EXPECT_EQ(test_uv_calls, 0u);
}

TEST_F(CtapBuiltInUvTest, ConfiguredGivesAToken) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(test_uv_calls, 1u);
	// {2: h'<32>'} (protocol one: no IV)
	EXPECT_TRUE(response_contains({0xa1, 0x02, 0x58, 0x20}));
	EXPECT_TRUE(ctap.pin_uv_auth_token_state.in_use);
	EXPECT_TRUE(ctap.pin_uv_auth_token_state.user_present);
}

TEST_F(CtapBuiltInUvTest, FailuresCountAndBlock) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	test_uv_result = CTAP_UP_RESULT_DENY;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_UV_INVALID);
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES - 1);
	ctap_init(&ctap); // kept across a power cycle
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES - 1);
	for (int i = 1; i < CTAP_UV_MAX_RETRIES - 1; ++i) {
		uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
		EXPECT_EQ(status, CTAP2_ERR_UV_INVALID);
	}
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_UV_BLOCKED);
	EXPECT_EQ(uv_retries(), 0);
	// blocked: not even asked
	test_uv_result = CTAP_UP_RESULT_ALLOW;
	const unsigned calls = test_uv_calls;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_UV_BLOCKED);
	EXPECT_EQ(test_uv_calls, calls);
	// a reset clears it
	request(CTAP_CMD_RESET, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES);
}

TEST_F(CtapBuiltInUvTest, SuccessResetsTheFailures) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	test_uv_result = CTAP_UP_RESULT_DENY;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES - 2);
	test_uv_result = CTAP_UP_RESULT_ALLOW;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES);
}

TEST_F(CtapBuiltInUvTest, TimeoutDoesNotCount) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	test_uv_result = CTAP_UP_RESULT_TIMEOUT;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_USER_ACTION_TIMEOUT);
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES);
}

TEST_F(CtapBuiltInUvTest, PermissionChecks) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg); // no uvAcfg
	EXPECT_EQ(status, CTAP2_ERR_UNAUTHORIZED_PERMISSION);
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr | CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_UNAUTHORIZED_PERMISSION);
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_mc); // mc without an RP ID
	EXPECT_EQ(status, CTAP1_ERR_INVALID_PARAMETER);
	uv_token(0);
	EXPECT_EQ(status, CTAP1_ERR_INVALID_PARAMETER);
	EXPECT_EQ(test_uv_calls, 0u);
}

TEST_F(CtapBuiltInUvTest, Versions) {
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(response_contains(text("FIDO_2_0")));
	EXPECT_TRUE(response_contains(text("FIDO_2_3")));
	EXPECT_TRUE(response_contains(text("FIDO_2_1")));
	EXPECT_FALSE(response_contains(text("FIDO_2_2"))); // no such version string
	EXPECT_FALSE(response_contains(text("U2F_V2")));
	ctap.ctap1_supported = true;
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(response_contains(text("U2F_V2")));
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
}

TEST_F(CtapBuiltInUvTest, CancelDoesNotCount) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	test_uv_result = CTAP_UP_RESULT_CANCEL;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	EXPECT_EQ(status, CTAP2_ERR_KEEPALIVE_CANCEL);
	EXPECT_EQ(test_uv_calls, 1u);
	EXPECT_FALSE(ctap.pin_uv_auth_token_state.in_use);
	EXPECT_EQ(uv_retries(), CTAP_UV_MAX_RETRIES);
}

TEST_F(CtapBuiltInUvTest, BeAndLbwAreRefused) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_be); // no uvBioEnroll
	EXPECT_EQ(status, CTAP2_ERR_UNAUTHORIZED_PERMISSION);
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_lbw); // no largeBlobs
	EXPECT_EQ(status, CTAP2_ERR_UNAUTHORIZED_PERMISSION);
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_cm | CTAP_clientPIN_pinUvAuthToken_permission_be);
	EXPECT_EQ(status, CTAP2_ERR_UNAUTHORIZED_PERMISSION);
	EXPECT_EQ(test_uv_calls, 0u);
}

TEST_F(CtapBuiltInUvTest, MissingParameters) {
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	// no keyAgreement: {1: 1, 2: 6, 9: cm}
	bytes r{0xa3, 0x01, 0x01, 0x02, 0x06};
	append_permissions(r, CTAP_clientPIN_pinUvAuthToken_permission_cm);
	request(CTAP_CMD_CLIENT_PIN, r);
	EXPECT_EQ(status, CTAP2_ERR_MISSING_PARAMETER);
	// no permissions: {1: 1, 2: 6, 3: key}
	r = {0xa3, 0x01, 0x01, 0x02, 0x06};
	const bytes k = key_agreement();
	r.insert(r.end(), k.begin(), k.end());
	request(CTAP_CMD_CLIENT_PIN, r);
	EXPECT_EQ(status, CTAP2_ERR_MISSING_PARAMETER);
	EXPECT_EQ(test_uv_requests, 2u); // told even then
	EXPECT_EQ(test_uv_calls, 0u);
}

TEST_F(CtapBuiltInUvTest, PcmrGivesThePersistentToken) {
	const std::string pin = "4826";
	set_pin(pin);
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	const bytes shared = shared_secret();
	uv_token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(test_uv_calls, 1u);
	const bytes persistent = decrypt_token(shared);
	ASSERT_EQ(persistent.size(), 32u);
	EXPECT_TRUE(ctap.persistent_pin_uv_auth_tokens_ready);
	EXPECT_FALSE(ctap.pin_uv_auth_token_state.in_use); // the regular token is left as it is
	// the same token as a PIN pcmr request gets
	EXPECT_EQ(pin_token(pin, CTAP_clientPIN_pinUvAuthToken_permission_pcmr), persistent);
	// good for read-only credential management
	get_creds_metadata(persistent);
	EXPECT_EQ(status, CTAP2_OK);
}

TEST_F(CtapBuiltInUvTest, GetInfoConfigured) {
	ctap.uv_modality = 0x0200; // more than one byte
	uint64_t modality = 0;
	EXPECT_FALSE(get_info_uint(CTAP_authenticatorGetInfo_res_uvModality, modality)); // NONE: absent
	ctap.built_in_uv = CTAP_BUILT_IN_UV_CONFIGURED;
	ASSERT_TRUE(get_info_uint(CTAP_authenticatorGetInfo_res_uvModality, modality));
	EXPECT_EQ(modality, 0x0200u);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	bytes uv_true = text("uv");
	uv_true.push_back(0xf5);
	EXPECT_TRUE(response_contains(uv_true));
}

} // namespace
