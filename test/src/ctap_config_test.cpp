#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <optional>
#include <vector>
extern "C" {
#include <ctap.h>
#include <ctap_crypto_software.h>
#include <ctap_memory_storage.h>
#include <ctap_test.h>
#include <hmac.h>
#include <sha256.h>
}
namespace {

// authenticatorConfig (0x0D): toggleAlwaysUv, setMinPINLength, enableLongTouchForReset
class CtapConfigTest : public testing::Test {
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
	CborParser parser{}; // the CborValues get_info_member() returns point into it

	CtapConfigTest() {
		test_reset_user_presence();
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	void request(uint8_t cmd, const std::vector<uint8_t> &params = {}) {
		status = ctap_request(&ctap, cmd, params.size(), params.empty() ? nullptr : params.data(), &response);
	}

	// a PIN of `code_points` code points (the hash does not matter here)
	void set_pin(uint8_t code_points = 6) {
		ctap.pin_state.is_pin_set = 1u;
		ctap.pin_state.pin_code_point_length = code_points;
		ctap_update_pin_persistent_state(&ctap);
	}

	// a pinUvAuthToken in use with `permissions`, for PIN/UV auth protocol 2
	void begin_token(uint32_t permissions) {
		ctap_pin_protocol_t *const p = &ctap.pin_protocols[1];
		p->reset_pin_uv_auth_token(p);
		ctap_pin_uv_auth_token_begin_using(&ctap, false, permissions);
	}

	// protocol 2: HMAC-SHA-256(pinUvAuthToken, 32 x 0xff || 0x0d || subCommand || subCommandParams)
	std::vector<uint8_t> auth_param(uint8_t sub_command, const std::vector<uint8_t> &sub_params) {
		std::vector<uint8_t> message(32, 0xff);
		message.push_back(CTAP_CMD_CONFIG);
		message.push_back(sub_command);
		message.insert(message.end(), sub_params.begin(), sub_params.end());
		const hash_alg_t *const sha256 = &hash_alg_sha256;
		std::vector<uint8_t> sha256_ctx(sha256->ctx_size);
		std::vector<uint8_t> hmac_ctx(hmac_get_context_size(sha256));
		std::vector<uint8_t> out(32);
		const ctap_pin_protocol_t *const p = &ctap.pin_protocols[1];
		hmac_init(hmac_ctx.data(), sha256, sha256_ctx.data(), p->pin_uv_auth_token, sizeof(p->pin_uv_auth_token));
		hmac_update(hmac_ctx.data(), message.data(), message.size());
		hmac_final(hmac_ctx.data(), out.data());
		return out;
	}

	// {1: sub_command, 2: sub_params (raw CBOR map, if any), 3: 2, 4: auth (if any)}
	static std::vector<uint8_t> config_request(
		uint8_t sub_command,
		const std::vector<uint8_t> &sub_params,
		const std::optional<std::vector<uint8_t>> &auth,
		bool with_protocol = true
	) {
		std::vector<uint8_t> r;
		const uint8_t n = 1 + (sub_params.empty() ? 0 : 1) + (auth ? (with_protocol ? 2 : 1) : 0);
		r.push_back(0xa0 | n);
		r.push_back(0x01);
		if (sub_command < 24) {
			r.push_back(sub_command);
		} else {
			r.push_back(0x18);
			r.push_back(sub_command);
		}
		if (!sub_params.empty()) {
			r.push_back(0x02);
			r.insert(r.end(), sub_params.begin(), sub_params.end());
		}
		if (auth) {
			if (with_protocol) {
				r.push_back(0x03);
				r.push_back(0x02);
			}
			r.push_back(0x04);
			r.push_back(0x58);
			r.push_back(static_cast<uint8_t>(auth->size()));
			r.insert(r.end(), auth->begin(), auth->end());
		}
		return r;
	}

	// a config request authenticated with the current token
	void config(uint8_t sub_command, const std::vector<uint8_t> &sub_params = {}) {
		request(CTAP_CMD_CONFIG, config_request(sub_command, sub_params, auth_param(sub_command, sub_params)));
	}

	// a config request without pinUvAuthParam
	void config_unauthenticated(uint8_t sub_command, const std::vector<uint8_t> &sub_params = {}) {
		request(CTAP_CMD_CONFIG, config_request(sub_command, sub_params, std::nullopt));
	}

	// getInfo member `key`, or nothing when absent
	std::optional<CborValue> get_info_member(uint64_t key) {
		request(CTAP_CMD_GET_INFO);
		EXPECT_EQ(status, CTAP2_OK);
		CborValue it;
		EXPECT_EQ(cbor_parser_init(response.data, response.length, 0, &parser, &it), CborNoError);
		CborValue map;
		EXPECT_EQ(cbor_value_enter_container(&it, &map), CborNoError);
		while (!cbor_value_at_end(&map)) {
			uint64_t member_key;
			EXPECT_EQ(cbor_value_get_uint64(&map, &member_key), CborNoError);
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
			if (member_key == key) {
				return map;
			}
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
		}
		return std::nullopt;
	}

	bool get_info_bool(uint64_t key) {
		auto value = get_info_member(key);
		EXPECT_TRUE(value.has_value());
		bool b = false;
		if (value) {
			EXPECT_EQ(cbor_value_get_boolean(&*value, &b), CborNoError);
		}
		return b;
	}

	// getInfo options[name], or nothing when absent
	std::optional<bool> get_info_option(const char *name) {
		auto options = get_info_member(CTAP_authenticatorGetInfo_res_options);
		EXPECT_TRUE(options.has_value());
		CborValue element;
		EXPECT_EQ(cbor_value_map_find_value(&*options, name, &element), CborNoError);
		if (cbor_value_get_type(&element) == CborInvalidType) {
			return std::nullopt;
		}
		bool b = false;
		EXPECT_EQ(cbor_value_get_boolean(&element, &b), CborNoError);
		return b;
	}

};

// {1: n}
std::vector<uint8_t> min_pin_length(uint8_t n) {
	if (n < 24) {
		return {0xa1, 0x01, n};
	}
	return {0xa1, 0x01, 0x18, n};
}

TEST_F(CtapConfigTest, GetInfoAdvertisesConfig) {
	request(CTAP_CMD_GET_INFO);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	EXPECT_EQ(get_info_option("authnrCfg"), std::optional<bool>(true));
	EXPECT_EQ(get_info_option("setMinPINLength"), std::optional<bool>(true));
	EXPECT_EQ(get_info_option("alwaysUv"), std::optional<bool>(false));
	EXPECT_EQ(get_info_option("makeCredUvNotRqd"), std::optional<bool>(true));
	EXPECT_FALSE(get_info_bool(CTAP_authenticatorGetInfo_res_forcePINChange));
	EXPECT_FALSE(get_info_bool(CTAP_authenticatorGetInfo_res_longTouchForReset));
	auto max_rp_ids = get_info_member(CTAP_authenticatorGetInfo_res_maxRPIDsForSetMinPINLength);
	ASSERT_TRUE(max_rp_ids.has_value());
	uint64_t n = 99;
	EXPECT_EQ(cbor_value_get_uint64(&*max_rp_ids, &n), CborNoError);
	EXPECT_EQ(n, 0u);
	auto commands = get_info_member(CTAP_authenticatorGetInfo_res_authenticatorConfigCommands);
	ASSERT_TRUE(commands.has_value());
	size_t length = 0;
	EXPECT_EQ(cbor_value_get_array_length(&*commands, &length), CborNoError);
	EXPECT_EQ(length, 3u);
}

TEST_F(CtapConfigTest, NoParameters) {
	request(CTAP_CMD_CONFIG);
	EXPECT_EQ(status, CTAP2_ERR_MISSING_PARAMETER);
}

TEST_F(CtapConfigTest, MissingSubCommand) {
	request(CTAP_CMD_CONFIG, {0xa1, 0x03, 0x02});
	EXPECT_EQ(status, CTAP2_ERR_MISSING_PARAMETER);
}

TEST_F(CtapConfigTest, UnsupportedSubCommands) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_enableEnterpriseAttestation);
	EXPECT_EQ(status, CTAP1_ERR_INVALID_PARAMETER);
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_vendorPrototype, {0xa1, 0x01, 0x01});
	EXPECT_EQ(status, CTAP1_ERR_INVALID_PARAMETER);
	config_unauthenticated(0x05);
	EXPECT_EQ(status, CTAP1_ERR_INVALID_PARAMETER);
}

TEST_F(CtapConfigTest, WithoutPinNoAuthIsNeeded) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(get_info_option("alwaysUv"), std::optional<bool>(true));
	EXPECT_EQ(get_info_option("makeCredUvNotRqd"), std::optional<bool>(false));
}

TEST_F(CtapConfigTest, AlwaysUvWithoutPinCanStillBeTurnedOff) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	ASSERT_EQ(status, CTAP2_OK);
	// Step 3: toggleAlwaysUv skips the auth then, any other subcommand needs it
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(6));
	EXPECT_EQ(status, CTAP2_ERR_PUAT_REQUIRED);
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(get_info_option("alwaysUv"), std::optional<bool>(false));
}

TEST_F(CtapConfigTest, WithPinAuthIsRequired) {
	set_pin();
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	EXPECT_EQ(status, CTAP2_ERR_PUAT_REQUIRED);
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg);
	auto auth = auth_param(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv, {});
	request(CTAP_CMD_CONFIG, config_request(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv, {}, auth, false));
	EXPECT_EQ(status, CTAP2_ERR_MISSING_PARAMETER);
	EXPECT_FALSE(ctap_is_always_uv(&ctap));
}

TEST_F(CtapConfigTest, WrongAuthParam) {
	set_pin();
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg);
	auto auth = auth_param(CTAP_authenticatorConfig_subCmd_setMinPINLength, {});
	request(CTAP_CMD_CONFIG, config_request(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv, {}, auth));
	EXPECT_EQ(status, CTAP2_ERR_PIN_AUTH_INVALID);
	EXPECT_FALSE(ctap_is_always_uv(&ctap));
}

TEST_F(CtapConfigTest, AuthCoversSubCommandParams) {
	set_pin(4);
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg);
	auto auth = auth_param(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(6));
	request(CTAP_CMD_CONFIG, config_request(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(7), auth));
	EXPECT_EQ(status, CTAP2_ERR_PIN_AUTH_INVALID);
	EXPECT_EQ(ctap_get_pin_min_code_point_length(&ctap), 4);
}

TEST_F(CtapConfigTest, TokenWithoutAcfgPermission) {
	set_pin();
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_cm);
	config(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	EXPECT_EQ(status, CTAP2_ERR_PIN_AUTH_INVALID);
}

TEST_F(CtapConfigTest, ToggleAlwaysUvAndBack) {
	set_pin();
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg);
	config(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(ctap_is_always_uv(&ctap));
	config(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_FALSE(ctap_is_always_uv(&ctap));
}

TEST_F(CtapConfigTest, ConfigSurvivesInitAndResetClearsIt) {
	// long touch first: with alwaysUv on, every other subcommand needs a pinUvAuthParam
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_enableLongTouchForReset);
	ASSERT_EQ(status, CTAP2_OK);
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	ASSERT_EQ(status, CTAP2_OK);
	ctap_init(&ctap);
	EXPECT_TRUE(ctap_is_always_uv(&ctap));
	EXPECT_EQ(ctap_get_long_touch_for_reset_ms(&ctap), 5000u);
	request(CTAP_CMD_RESET);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(test_long_touch_calls, 1u);
	EXPECT_FALSE(ctap_is_always_uv(&ctap));
	EXPECT_EQ(ctap_get_long_touch_for_reset_ms(&ctap), 0u);
}

TEST_F(CtapConfigTest, EnableLongTouchForReset) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_enableLongTouchForReset);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(get_info_bool(CTAP_authenticatorGetInfo_res_longTouchForReset));
}

TEST_F(CtapConfigTest, SetMinPinLengthRaisesIt) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(6));
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(ctap_get_pin_min_code_point_length(&ctap), 6);
	EXPECT_FALSE(ctap_is_force_pin_change(&ctap)); // no PIN
	ctap_init(&ctap);
	EXPECT_EQ(ctap_get_pin_min_code_point_length(&ctap), 6);
}

TEST_F(CtapConfigTest, SetMinPinLengthNeverLowersIt) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(6));
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(5));
	EXPECT_EQ(status, CTAP2_ERR_PIN_POLICY_VIOLATION);
	EXPECT_EQ(ctap_get_pin_min_code_point_length(&ctap), 6);
}

TEST_F(CtapConfigTest, SetMinPinLengthAboveTheMaximum) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(64));
	EXPECT_EQ(status, CTAP2_ERR_PIN_POLICY_VIOLATION);
}

TEST_F(CtapConfigTest, SetMinPinLengthRefusesRpIds) {
	// {2: ["example.com"]}: the minPinLength extension is not supported
	config_unauthenticated(
		CTAP_authenticatorConfig_subCmd_setMinPINLength,
		{0xa1, 0x02, 0x81, 0x6b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}
	);
	EXPECT_EQ(status, CTAP1_ERR_INVALID_PARAMETER);
}

TEST_F(CtapConfigTest, ForceChangePinWithoutPin) {
	// {3: true}
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, {0xa1, 0x03, 0xf5});
	EXPECT_EQ(status, CTAP2_ERR_PIN_NOT_SET);
}

TEST_F(CtapConfigTest, ForceChangePin) {
	set_pin();
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg);
	config(CTAP_authenticatorConfig_subCmd_setMinPINLength, {0xa1, 0x03, 0xf5});
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(ctap_is_force_pin_change(&ctap));
	EXPECT_TRUE(get_info_bool(CTAP_authenticatorGetInfo_res_forcePINChange));
	// all pinUvAuthTokens were reset
	EXPECT_FALSE(ctap.pin_uv_auth_token_state.in_use);
}

TEST_F(CtapConfigTest, MinLengthAboveThePinForcesAChange) {
	set_pin(4);
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg);
	config(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(6));
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(ctap_is_force_pin_change(&ctap));
}

TEST_F(CtapConfigTest, MinLengthNotAboveThePinDoesNotForceAChange) {
	set_pin(6);
	begin_token(CTAP_clientPIN_pinUvAuthToken_permission_acfg);
	config(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(6));
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_FALSE(ctap_is_force_pin_change(&ctap));
	EXPECT_TRUE(ctap.pin_uv_auth_token_state.in_use);
}

// alwaysUv in makeCredential / getAssertion

TEST_F(CtapConfigTest, AlwaysUvMakeCredentialNeedsPinUvAuthParam) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	// {1: h'00..', 2: {"id": "a.b"}, 3: {"id": h'01'}, 4: [{"alg": -7, "type": "public-key"}]}
	auto params = hex::bytes<
		"a4"
		"  01 5820 0000000000000000000000000000000000000000000000000000000000000000"
		"  02 a1 62 6964 63 612e62"
		"  03 a1 62 6964 41 01"
		"  04 81 a2 63 616c67 26 64 74797065 6a 7075626c69632d6b6579"
	>();
	request(CTAP_CMD_MAKE_CREDENTIAL, std::vector<uint8_t>(params.begin(), params.end()));
	EXPECT_EQ(status, CTAP2_ERR_PUAT_REQUIRED);
}

TEST_F(CtapConfigTest, WithoutAlwaysUvMakeCredentialWorks) {
	auto params = hex::bytes<
		"a4"
		"  01 5820 0000000000000000000000000000000000000000000000000000000000000000"
		"  02 a1 62 6964 63 612e62"
		"  03 a1 62 6964 41 01"
		"  04 81 a2 63 616c67 26 64 74797065 6a 7075626c69632d6b6579"
	>();
	request(CTAP_CMD_MAKE_CREDENTIAL, std::vector<uint8_t>(params.begin(), params.end()));
	EXPECT_EQ(status, CTAP2_OK);
}

TEST_F(CtapConfigTest, AlwaysUvGetAssertionWithUpNeedsPinUvAuthParam) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	// {1: "a.b", 2: h'00..', 5: {"up": true}}
	auto params = hex::bytes<
		"a3"
		"  01 63 612e62"
		"  02 5820 0000000000000000000000000000000000000000000000000000000000000000"
		"  05 a1 62 7570 f5"
	>();
	request(CTAP_CMD_GET_ASSERTION, std::vector<uint8_t>(params.begin(), params.end()));
	EXPECT_EQ(status, CTAP2_ERR_PUAT_REQUIRED);
}

TEST_F(CtapConfigTest, AlwaysUvGetAssertionWithoutUpOptionIsNotAffected) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_toggleAlwaysUv);
	// {1: "a.b", 2: h'00..'}: no credentials, but past Step 5
	auto params = hex::bytes<
		"a2"
		"  01 63 612e62"
		"  02 5820 0000000000000000000000000000000000000000000000000000000000000000"
	>();
	request(CTAP_CMD_GET_ASSERTION, std::vector<uint8_t>(params.begin(), params.end()));
	EXPECT_EQ(status, CTAP2_ERR_NO_CREDENTIALS);
}

// the reset window (ctap_state_t.reset_window_ms)

TEST_F(CtapConfigTest, ResetWindowNone) {
	ctap.reset_window_ms = CTAP_RESET_WINDOW_NONE;
	test_current_time = 3600u * 1000u;
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_OK);
}

TEST_F(CtapConfigTest, ResetWindowLonger) {
	ctap.reset_window_ms = 30000u;
	test_current_time = 20000u;
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_OK);
	test_current_time = 20000u + 30001u; // reset restarts the window (ctap_init)
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_ERR_NOT_ALLOWED);
}

} // namespace
