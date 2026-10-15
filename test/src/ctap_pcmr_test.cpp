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

// pcmr (CTAP 2.2): the persistentPinUvAuthToken, read-only credential management

using bytes = std::vector<uint8_t>;

constexpr auto platform_private_key = hex::bytes<
	"b6a7164827e98933906aa13b90dd8bf6a15989a3419d90ecc1cde95a80aefb6c"
>();
constexpr auto platform_public_x = hex::bytes<
	"bcfd95db7be64d2dc19d450b87635f9dfc5a4a7c872c3a66cc98e2f724799095"
>();
constexpr auto platform_public_y = hex::bytes<
	"d55c3641e99a6ca1ebe9bc6600df3de0f2e3be334359c7422bff873f341f379b"
>();

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

class CtapPcmrTest : public testing::Test {
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
	const std::string pin = "4826";

	CtapPcmrTest() {
		test_reset_user_presence();
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
		// a PIN, set directly: CurrentStoredPIN = LEFT(SHA-256(PIN), 16)
		const bytes hash = sha256(bytes(pin.begin(), pin.end()));
		std::copy(hash.begin(), hash.begin() + 16, ctap.pin_state.pin_hash);
		ctap.pin_state.pin_code_point_length = static_cast<uint8_t>(pin.size());
		ctap.pin_state.is_pin_set = 1u;
		ctap_update_pin_persistent_state(&ctap);
	}

	void request(uint8_t cmd, const bytes &params) {
		status = ctap_request(&ctap, cmd, params.size(), params.data(), &response);
	}

	// protocol one: SHA-256 of the ECDH x with the authenticator's key-agreement key
	bytes shared_secret() {
		request(CTAP_CMD_CLIENT_PIN, {0xa2, 0x01, 0x01, 0x02, 0x02});
		EXPECT_EQ(status, CTAP2_OK);
		const bytes r(response.data, response.data + response.length);
		const bytes x_label{0x21, 0x58, 0x20};
		const bytes y_label{0x22, 0x58, 0x20};
		auto x = std::search(r.begin(), r.end(), x_label.begin(), x_label.end());
		auto y = std::search(r.begin(), r.end(), y_label.begin(), y_label.end());
		uint8_t authenticator_public[64];
		std::copy(x + 3, x + 35, authenticator_public);
		std::copy(y + 3, y + 35, authenticator_public + 32);
		uint8_t z[32];
		EXPECT_EQ(uECC_shared_secret(
			authenticator_public, platform_private_key.data(), z, uECC_secp256r1(), test_rng, nullptr
		), 1);
		return sha256(bytes(z, z + 32));
	}

	// getPinUvAuthTokenUsingPinWithPermissions (protocol one): the decrypted token, or empty
	bytes token(uint8_t permissions) {
		const bytes shared = shared_secret();
		const bytes pin_hash = sha256(bytes(pin.begin(), pin.end()));
		const bytes pin_hash_enc = aes_cbc(shared, bytes(pin_hash.begin(), pin_hash.begin() + 16), true);
		bytes r{0xa5, 0x01, 0x01, 0x02, 0x09, 0x03, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20};
		r.insert(r.end(), platform_public_x.begin(), platform_public_x.end());
		r.insert(r.end(), {0x22, 0x58, 0x20});
		r.insert(r.end(), platform_public_y.begin(), platform_public_y.end());
		r.push_back(0x06);
		append_bstr(r, pin_hash_enc);
		r.push_back(0x09);
		if (permissions < 24) {
			r.push_back(permissions);
		} else {
			r.insert(r.end(), {0x18, permissions});
		}
		if (permissions & (CTAP_clientPIN_pinUvAuthToken_permission_mc | CTAP_clientPIN_pinUvAuthToken_permission_ga)) {
			r[0] = 0xa6;
			r.insert(r.end(), {0x0a, 0x63, 'a', '.', 'b'});
		}
		request(CTAP_CMD_CLIENT_PIN, r);
		if (status != CTAP2_OK) {
			return {};
		}
		// {2: h'<32>'}
		const bytes enc(response.data + 4, response.data + 4 + 32); // a1 02 58 20
		return aes_cbc(shared, enc, false);
	}

	// authenticatorCredentialManagement with pinUvAuthParam = LEFT(HMAC(token, subCommand || params), 16)
	void cred_mgmt(const bytes &token, uint8_t sub_command, const bytes &sub_params = {}) {
		bytes message{sub_command};
		message.insert(message.end(), sub_params.begin(), sub_params.end());
		const bytes mac = hmac_sha256(token, message);
		bytes r{static_cast<uint8_t>(sub_params.empty() ? 0xa3 : 0xa4), 0x01, sub_command};
		if (!sub_params.empty()) {
			r.push_back(0x02);
			r.insert(r.end(), sub_params.begin(), sub_params.end());
		}
		r.insert(r.end(), {0x03, 0x01, 0x04});
		append_bstr(r, bytes(mac.begin(), mac.begin() + 16));
		request(CTAP_CMD_CREDENTIAL_MANAGEMENT, r);
	}
};

TEST_F(CtapPcmrTest, GetInfoAdvertisesIt) {
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	const bytes r(response.data, response.data + response.length);
	const std::string id = "perCredMgmtRO";
	bytes needle{static_cast<uint8_t>(0x60 | id.size())};
	needle.insert(needle.end(), id.begin(), id.end());
	needle.push_back(0xf5);
	EXPECT_NE(std::search(r.begin(), r.end(), needle.begin(), needle.end()), r.end());
}

TEST_F(CtapPcmrTest, PcmrOnlyAlone) {
	EXPECT_TRUE(token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr | CTAP_clientPIN_pinUvAuthToken_permission_cm).empty());
	EXPECT_EQ(status, CTAP2_ERR_UNAUTHORIZED_PERMISSION);
}

TEST_F(CtapPcmrTest, ReadsWithThePersistentToken) {
	const bytes persistent = token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(persistent.size(), 32u);
	cred_mgmt(persistent, CTAP_credentialManagement_subCmd_getCredsMetadata);
	EXPECT_EQ(status, CTAP2_OK);
	cred_mgmt(persistent, CTAP_credentialManagement_subCmd_enumerateRPsBegin);
	EXPECT_EQ(status, CTAP2_ERR_NO_CREDENTIALS); // authorized, nothing stored
	// {1: h'<32>'} rpIDHash
	bytes rp_params{0xa1, 0x01, 0x58, 0x20};
	rp_params.insert(rp_params.end(), 32, 0x33);
	cred_mgmt(persistent, CTAP_credentialManagement_subCmd_enumerateCredentialsBegin, rp_params);
	EXPECT_EQ(status, CTAP2_ERR_NO_CREDENTIALS);
}

TEST_F(CtapPcmrTest, CannotDelete) {
	const bytes persistent = token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(persistent.size(), 32u);
	// {2: {"id": h'<32>', "type": "public-key"}}
	bytes params{0xa1, 0x02, 0xa2, 0x62, 'i', 'd', 0x58, 0x20};
	params.insert(params.end(), 32, 0x44);
	params.insert(params.end(), {0x64, 't', 'y', 'p', 'e', 0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
	cred_mgmt(persistent, CTAP_credentialManagement_subCmd_deleteCredential, params);
	EXPECT_EQ(status, CTAP2_ERR_PIN_AUTH_INVALID);
}

TEST_F(CtapPcmrTest, TheRegularTokenStays) {
	const bytes regular = token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	ASSERT_EQ(regular.size(), 32u);
	const bytes persistent = token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(persistent.size(), 32u);
	EXPECT_NE(regular, persistent);
	cred_mgmt(regular, CTAP_credentialManagement_subCmd_getCredsMetadata);
	EXPECT_EQ(status, CTAP2_OK);
}

TEST_F(CtapPcmrTest, SurvivesInitAndIsTheSameNextTime) {
	const bytes persistent = token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(persistent.size(), 32u);
	ctap_init(&ctap); // a power cycle
	cred_mgmt(persistent, CTAP_credentialManagement_subCmd_getCredsMetadata);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr), persistent);
}

TEST_F(CtapPcmrTest, ResetByForcePinChange) {
	const bytes persistent = token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(persistent.size(), 32u);
	ctap_reset_persistent_pin_uv_auth_tokens(&ctap); // what changePIN and setMinPINLength (force) call
	cred_mgmt(persistent, CTAP_credentialManagement_subCmd_getCredsMetadata);
	EXPECT_EQ(status, CTAP2_ERR_PIN_AUTH_INVALID);
	ctap_init(&ctap);
	cred_mgmt(persistent, CTAP_credentialManagement_subCmd_getCredsMetadata);
	EXPECT_EQ(status, CTAP2_ERR_PIN_AUTH_INVALID);
	// a new one
	const bytes fresh = token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(fresh.size(), 32u);
	EXPECT_NE(fresh, persistent);
}

TEST_F(CtapPcmrTest, ResetMakesItInvalid) {
	const bytes persistent = token(CTAP_clientPIN_pinUvAuthToken_permission_pcmr);
	ASSERT_EQ(persistent.size(), 32u);
	request(CTAP_CMD_RESET, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_FALSE(ctap.persistent_pin_uv_auth_tokens_ready);
}

} // namespace
