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

constexpr auto platform_public_x = hex::bytes<
	"bcfd95db7be64d2dc19d450b87635f9dfc5a4a7c872c3a66cc98e2f724799095"
>();
constexpr auto platform_public_y = hex::bytes<
	"d55c3641e99a6ca1ebe9bc6600df3de0f2e3be334359c7422bff873f341f379b"
>();

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

	// clientPIN getPinUvAuthTokenUsingUvWithPermissions (protocol one)
	void uv_token(uint8_t permissions) {
		bytes r{0xa4, 0x01, 0x01, 0x02, 0x06, 0x03, 0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20};
		r.insert(r.end(), platform_public_x.begin(), platform_public_x.end());
		r.insert(r.end(), {0x22, 0x58, 0x20});
		r.insert(r.end(), platform_public_y.begin(), platform_public_y.end());
		r.push_back(0x09);
		if (permissions < 24) {
			r.push_back(permissions);
		} else {
			r.insert(r.end(), {0x18, permissions});
		}
		request(CTAP_CMD_CLIENT_PIN, r);
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

} // namespace
