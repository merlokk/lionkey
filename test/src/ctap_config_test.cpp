#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
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

public:
	// makeCredential (rp `rp_id`, 3 bytes) with {"minPinLength": true}: the authenticator data
	std::vector<uint8_t> make_credential_with_min_pin_length(const char *rp_id) {
		return make_credential_with(rp_id, "minPinLength");
	}

	// makeCredential (rp `rp_id`, 3 bytes) with {`extension`: true}: the authenticator data
	std::vector<uint8_t> make_credential_with(const char *rp_id, const std::string &extension) {
		std::vector<uint8_t> r = {0xa5, 0x01, 0x58, 0x20};
		r.insert(r.end(), 32, 0x00);
		r.insert(r.end(), {0x02, 0xa1, 0x62, 'i', 'd', 0x63});
		r.insert(r.end(), rp_id, rp_id + 3);
		r.insert(r.end(), {0x03, 0xa1, 0x62, 'i', 'd', 0x41, 0x01});
		r.insert(r.end(), {0x04, 0x81, 0xa2, 0x63, 'a', 'l', 'g', 0x26, 0x64, 't', 'y', 'p', 'e',
			0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
		r.insert(r.end(), {0x06, 0xa1});
		r.push_back(static_cast<uint8_t>(0x60 | extension.size())); // < 24 bytes
		r.insert(r.end(), extension.begin(), extension.end());
		r.push_back(0xf5);
		request(CTAP_CMD_MAKE_CREDENTIAL, r);
		EXPECT_EQ(status, CTAP2_OK);
		if (status != CTAP2_OK) {
			return {};
		}
		CborValue it;
		EXPECT_EQ(cbor_parser_init(response.data, response.length, 0, &parser, &it), CborNoError);
		// {1: fmt, 2: authData, 3: attStmt}: walk to key 2
		CborValue map;
		EXPECT_EQ(cbor_value_enter_container(&it, &map), CborNoError);
		while (!cbor_value_at_end(&map)) {
			uint64_t key;
			EXPECT_EQ(cbor_value_get_uint64(&map, &key), CborNoError);
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
			if (key == 2) {
				size_t n = 0;
				EXPECT_EQ(cbor_value_calculate_string_length(&map, &n), CborNoError);
				std::vector<uint8_t> out(n);
				EXPECT_EQ(cbor_value_copy_byte_string(&map, out.data(), &n, nullptr), CborNoError);
				return out;
			}
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
		}
		ADD_FAILURE() << "no authData";
		return {};
	}
	static constexpr uint8_t min_pin_length_key_bytes[13] = {
		0x6c, 'm', 'i', 'n', 'P', 'i', 'n', 'L', 'e', 'n', 'g', 't', 'h'
	};
protected:

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
	EXPECT_EQ(n, 8u);
	auto extensions = get_info_member(CTAP_authenticatorGetInfo_res_extensions);
	ASSERT_TRUE(extensions.has_value());
	CborValue extension;
	ASSERT_EQ(cbor_value_enter_container(&*extensions, &extension), CborNoError);
	bool min_pin_length_listed = false;
	while (!cbor_value_at_end(&extension)) {
		bool equal = false;
		EXPECT_EQ(cbor_value_text_string_equals(&extension, "minPinLength", &equal), CborNoError);
		min_pin_length_listed |= equal;
		EXPECT_EQ(cbor_value_advance(&extension), CborNoError);
	}
	EXPECT_TRUE(min_pin_length_listed);
	auto commands = get_info_member(CTAP_authenticatorGetInfo_res_authenticatorConfigCommands);
	ASSERT_TRUE(commands.has_value());
	size_t length = 0;
	EXPECT_EQ(cbor_value_get_array_length(&*commands, &length), CborNoError);
	EXPECT_EQ(length, 3u);
	// [toggleAlwaysUv, setMinPINLength, enableLongTouchForReset]
	CborValue command;
	ASSERT_EQ(cbor_value_enter_container(&*commands, &command), CborNoError);
	std::vector<uint64_t> values;
	while (!cbor_value_at_end(&command)) {
		uint64_t value = 0;
		EXPECT_EQ(cbor_value_get_uint64(&command, &value), CborNoError);
		values.push_back(value);
		EXPECT_EQ(cbor_value_advance(&command), CborNoError);
	}
	EXPECT_EQ(values, (std::vector<uint64_t>{2, 3, 4}));
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

// {2: [rp_ids...]} (each RP ID shorter than 24 bytes)
std::vector<uint8_t> rp_ids_params(std::initializer_list<std::string> rp_ids) {
	std::vector<uint8_t> p{0xa1, 0x02, static_cast<uint8_t>(0x80 | rp_ids.size())};
	for (const auto &id : rp_ids) {
		p.push_back(static_cast<uint8_t>(0x60 | id.size()));
		p.insert(p.end(), id.begin(), id.end());
	}
	return p;
}

std::vector<uint8_t> make_credential_min_pin_length(CtapConfigTest *t, const char *rp_id) {
	return t->make_credential_with_min_pin_length(rp_id);
}

std::vector<uint8_t> make_credential_with_extension(CtapConfigTest *t, const char *rp_id, const char *extension) {
	return t->make_credential_with(rp_id, extension);
}

TEST_F(CtapConfigTest, SetMinPinLengthStoresRpIds) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"a.b", "x.y"}));
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 2u);
	// a later list replaces it
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"c.d"}));
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 1u);
	// an empty one changes nothing
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, {0xa1, 0x02, 0x80});
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 1u);
}

TEST_F(CtapConfigTest, SetMinPinLengthTooManyRpIds) {
	config_unauthenticated(
		CTAP_authenticatorConfig_subCmd_setMinPINLength,
		rp_ids_params({"a.a", "b.b", "c.c", "d.d", "e.e", "f.f", "g.g", "h.h", "i.i"})
	);
	EXPECT_EQ(status, CTAP2_ERR_KEY_STORE_FULL);
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 0u);
	config_unauthenticated(
		CTAP_authenticatorConfig_subCmd_setMinPINLength,
		rp_ids_params({"a.a", "b.b", "c.c", "d.d", "e.e", "f.f", "g.g", "h.h"})
	);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 8u);
}

// a storage that refuses writes of one item key (the memory storage otherwise)
uint32_t refused_storage_key = 0;

ctap_storage_status_t refusing_create_or_update_item(const ctap_storage_t *storage, ctap_storage_item_t *item) {
	if (item->key == refused_storage_key) {
		return CTAP_STORAGE_ERROR;
	}
	return ctap_memory_storage_create_or_update_item(storage, item);
}

// a failed write leaves neither a raised minimum nor a new flag behind
// (no PIN, so no pinUvAuthParam: the flag is pinComplexityPolicy)
TEST_F(CtapConfigTest, SetMinPinLengthStorageFailureChangesNothing) {
	ctap_storage_t refusing_storage = storage;
	refusing_storage.create_or_update_item = refusing_create_or_update_item;
	ctap_state_t refusing_ctap = CTAP_STATE_CONST_INIT(&crypto, &refusing_storage);
	ctap_init(&refusing_ctap);
	// {1: 6, 2: ["a.b"], 4: true}
	const std::vector<uint8_t> params = config_request(
		CTAP_authenticatorConfig_subCmd_setMinPINLength,
		{0xa3, 0x01, 0x06, 0x02, 0x81, 0x63, 'a', '.', 'b', 0x04, 0xf5},
		std::nullopt
	);
	const auto send = [&](uint32_t key) {
		refused_storage_key = key;
		const uint8_t s = ctap_request(&refusing_ctap, CTAP_CMD_CONFIG, params.size(), params.data(), &response);
		refused_storage_key = 0;
		return s;
	};
	const auto expect_unchanged = [&]() {
		EXPECT_EQ(ctap_get_pin_min_code_point_length(&refusing_ctap), 4);
		EXPECT_FALSE(ctap_is_pin_complexity_policy(&refusing_ctap));
	};

	// the RP ID list cannot be stored: nothing is written
	EXPECT_EQ(send(CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS), CTAP2_ERR_KEY_STORE_FULL);
	expect_unchanged();
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&refusing_ctap), 0u);

	// the minimum cannot be stored: no flag after it
	EXPECT_EQ(send(CTAP_STORAGE_KEY_PIN_INFO), CTAP1_ERR_OTHER);
	expect_unchanged();
	ctap_init(&refusing_ctap);
	expect_unchanged();

	// nothing refused
	EXPECT_EQ(send(0), CTAP2_OK);
	EXPECT_EQ(ctap_get_pin_min_code_point_length(&refusing_ctap), 6);
	EXPECT_TRUE(ctap_is_pin_complexity_policy(&refusing_ctap));
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&refusing_ctap), 1u);
}

TEST_F(CtapConfigTest, SetMinPinLengthRpIdsMustBeStrings) {
	// {2: [1]}
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, {0xa1, 0x02, 0x81, 0x01});
	EXPECT_EQ(status, CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

TEST_F(CtapConfigTest, ResetClearsRpIds) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"a.b"}));
	ASSERT_EQ(status, CTAP2_OK);
	request(CTAP_CMD_RESET);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 0u);
}

// "minPinLength" as a CBOR text string
const std::vector<uint8_t> min_pin_length_key{
	0x6c, 'm', 'i', 'n', 'P', 'i', 'n', 'L', 'e', 'n', 'g', 't', 'h'
};

bool contains(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle) {
	return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

TEST_F(CtapConfigTest, MinPinLengthExtensionForAListedRp) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, min_pin_length(6));
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"a.b"}));
	ASSERT_EQ(status, CTAP2_OK);
	auto auth_data = make_credential_min_pin_length(this, "a.b");
	ASSERT_GT(auth_data.size(), 37u);
	EXPECT_NE(auth_data[32] & CTAP_authenticator_data_flags_ed, 0);
	auto expected = min_pin_length_key;
	expected.push_back(0x06);
	EXPECT_TRUE(contains(auth_data, expected));
}

TEST_F(CtapConfigTest, MinPinLengthExtensionForAnotherRpIsOmitted) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"x.y"}));
	ASSERT_EQ(status, CTAP2_OK);
	auto auth_data = make_credential_min_pin_length(this, "a.b");
	ASSERT_GT(auth_data.size(), 37u);
	EXPECT_EQ(auth_data[32] & CTAP_authenticator_data_flags_ed, 0);
	EXPECT_FALSE(contains(auth_data, min_pin_length_key));
}

TEST_F(CtapConfigTest, OnlyUnsupportedExtensionsGiveNoExtensionsInAuthData) {
	auto auth_data = make_credential_with_extension(this, "a.b", "unknownExt");
	ASSERT_GT(auth_data.size(), 55u);
	EXPECT_EQ(auth_data[32] & CTAP_authenticator_data_flags_ed, 0);
	EXPECT_NE(auth_data[32] & CTAP_authenticator_data_flags_at, 0);
	// rpIdHash (32) flags (1) signCount (4) aaguid (16) credentialIdLength (2) credentialId, then the
	// COSE public key ends the authenticator data (no extensions map after it)
	const size_t credential_id_length = (size_t(auth_data[53]) << 8) | auth_data[54];
	const size_t key_offset = 55 + credential_id_length;
	ASSERT_LT(key_offset, auth_data.size());
	CborParser key_parser;
	CborValue key;
	ASSERT_EQ(cbor_parser_init(&auth_data[key_offset], auth_data.size() - key_offset, 0, &key_parser, &key), CborNoError);
	EXPECT_TRUE(cbor_value_is_map(&key));
	ASSERT_EQ(cbor_value_advance(&key), CborNoError);
	EXPECT_TRUE(cbor_value_at_end(&key));
	EXPECT_EQ(cbor_value_get_next_byte(&key), auth_data.data() + auth_data.size());
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


// PIN complexity policy (pinComplexityPolicy)

TEST_F(CtapConfigTest, PinComplexityPolicyOffByDefault) {
	EXPECT_FALSE(get_info_bool(CTAP_authenticatorGetInfo_res_pinComplexityPolicy));
	EXPECT_FALSE(get_info_member(CTAP_authenticatorGetInfo_res_pinComplexityPolicyURL).has_value());
	request(CTAP_CMD_GET_INFO);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
}

TEST_F(CtapConfigTest, PinComplexityPolicyPreconfigured) {
	ctap.pin_complexity_policy_preconfigured = true;
	ctap.pin_complexity_policy_url = "https://example.com/pin";
	EXPECT_TRUE(get_info_bool(CTAP_authenticatorGetInfo_res_pinComplexityPolicy));
	auto url = get_info_member(CTAP_authenticatorGetInfo_res_pinComplexityPolicyURL);
	ASSERT_TRUE(url.has_value());
	EXPECT_TRUE(cbor_value_is_byte_string(&*url));
	request(CTAP_CMD_GET_INFO);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	const std::vector<uint8_t> data(response.data, response.data + response.length);
	const std::string id = "pinComplexityPolicy";
	EXPECT_TRUE(contains(data, std::vector<uint8_t>(id.begin(), id.end()))); // in extensions
	// a reset keeps the pre-configured value
	request(CTAP_CMD_RESET);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(ctap_is_pin_complexity_policy(&ctap));
}

TEST_F(CtapConfigTest, SetMinPinLengthEnablesPinComplexityPolicyUntilReset) {
	// {4: true}
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, {0xa1, 0x04, 0xf5});
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(get_info_bool(CTAP_authenticatorGetInfo_res_pinComplexityPolicy));
	// {4: false} does not turn it off
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, {0xa1, 0x04, 0xf4});
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(ctap_is_pin_complexity_policy(&ctap));
	ctap_init(&ctap);
	EXPECT_TRUE(ctap_is_pin_complexity_policy(&ctap));
	request(CTAP_CMD_RESET);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_FALSE(ctap_is_pin_complexity_policy(&ctap));
}

TEST_F(CtapConfigTest, PinComplexityPolicyExtensionForAListedRp) {
	ctap.pin_complexity_policy_preconfigured = true;
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"a.b"}));
	ASSERT_EQ(status, CTAP2_OK);
	auto auth_data = make_credential_with_extension(this, "a.b", "pinComplexityPolicy");
	const std::string id = "pinComplexityPolicy";
	std::vector<uint8_t> expected{0x73};
	expected.insert(expected.end(), id.begin(), id.end());
	expected.push_back(0xf5);
	EXPECT_TRUE(contains(auth_data, expected));
	auto other = make_credential_with_extension(this, "c.d", "pinComplexityPolicy");
	ASSERT_GT(other.size(), 37u);
	EXPECT_EQ(other[32] & CTAP_authenticator_data_flags_ed, 0);
}

TEST_F(CtapConfigTest, PinComplexityPolicyExtensionIsFalseWhenOff) {
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"a.b"}));
	ASSERT_EQ(status, CTAP2_OK);
	auto auth_data = make_credential_with_extension(this, "a.b", "pinComplexityPolicy");
	ASSERT_GT(auth_data.size(), 37u);
	EXPECT_NE(auth_data[32] & CTAP_authenticator_data_flags_ed, 0);
	const std::string id = "pinComplexityPolicy";
	std::vector<uint8_t> expected{0x73};
	expected.insert(expected.end(), id.begin(), id.end());
	expected.push_back(0xf4);
	EXPECT_TRUE(contains(auth_data, expected));
	// not in getInfo extensions while off
	request(CTAP_CMD_GET_INFO);
	ASSERT_EQ(status, CTAP2_OK);
	const std::vector<uint8_t> data(response.data, response.data + response.length);
	EXPECT_FALSE(contains(data, std::vector<uint8_t>(id.begin(), id.end())));
}

// fido.bin from before authenticatorConfig: a PIN and a credential, no CTAP_STORAGE_KEY_CONFIG (4)
// and no CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS (5) items
TEST_F(CtapConfigTest, StorageWithoutConfigItemsLoadsDefaults) {
	// {1: h'00..', 2: {"id": "a.b"}, 3: {"id": h'01'}, 4: [{"alg": -7, "type": "public-key"}], 7: {"rk": true}}
	auto params = hex::bytes<
		"a5"
		"  01 5820 0000000000000000000000000000000000000000000000000000000000000000"
		"  02 a1 62 6964 63 612e62"
		"  03 a1 62 6964 41 01"
		"  04 81 a2 63 616c67 26 64 74797065 6a 7075626c69632d6b6579"
		"  07 a1 62 726b f5"
	>();
	request(CTAP_CMD_MAKE_CREDENTIAL, std::vector<uint8_t>(params.begin(), params.end()));
	ASSERT_EQ(status, CTAP2_OK);
	config_unauthenticated(CTAP_authenticatorConfig_subCmd_setMinPINLength, rp_ids_params({"a.b"}));
	ASSERT_EQ(status, CTAP2_OK);
	set_pin(6);
	std::fill(std::begin(ctap.pin_state.pin_hash), std::end(ctap.pin_state.pin_hash), 0x5a);
	ctap_update_pin_persistent_state(&ctap);
	ctap.config_state.flags = CTAP_CONFIG_flags_always_uv
		| CTAP_CONFIG_flags_force_pin_change
		| CTAP_CONFIG_flags_pin_complexity_policy;
	ASSERT_TRUE(ctap_update_config_persistent_state(&ctap));
	ctap_init(&ctap);
	ASSERT_TRUE(ctap_is_always_uv(&ctap));
	ASSERT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 1u);
	// drop items 4 and 5 (what an old fido.bin looks like)
	for (const uint32_t key : {CTAP_STORAGE_KEY_CONFIG, CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS}) {
		ctap_storage_item_t item{.key = key};
		ASSERT_EQ(storage.find_item(&storage, &item), CTAP_STORAGE_OK);
		ASSERT_EQ(storage.delete_item(&storage, item.handle), CTAP_STORAGE_OK);
		ctap_storage_item_t again{.key = key};
		ASSERT_EQ(storage.find_item(&storage, &again), CTAP_STORAGE_ITEM_NOT_FOUND);
	}
	ctap_init(&ctap);
	EXPECT_FALSE(ctap_is_always_uv(&ctap));
	EXPECT_FALSE(ctap_is_force_pin_change(&ctap));
	EXPECT_FALSE(ctap_is_pin_complexity_policy(&ctap));
	EXPECT_EQ(ctap_get_long_touch_for_reset_ms(&ctap), 0u);
	EXPECT_EQ(ctap_get_pin_min_code_point_length(&ctap), 4);
	EXPECT_EQ(ctap_min_pin_length_rp_ids_count(&ctap), 0u);
	// the PIN is as it was
	EXPECT_TRUE(ctap_is_pin_set(&ctap));
	EXPECT_EQ(ctap.pin_state.pin_code_point_length, 6);
	EXPECT_EQ(ctap.pin_state.pin_total_remaining_attempts, CTAP_PIN_TOTAL_ATTEMPTS);
	const std::vector<uint8_t> pin_hash(std::begin(ctap.pin_state.pin_hash), std::end(ctap.pin_state.pin_hash));
	EXPECT_EQ(pin_hash, std::vector<uint8_t>(sizeof(ctap.pin_state.pin_hash), 0x5a));
	EXPECT_EQ(get_info_option("alwaysUv"), std::optional<bool>(false));
	EXPECT_FALSE(get_info_bool(CTAP_authenticatorGetInfo_res_forcePINChange));
	// and so is the credential: {1: "a.b", 2: h'00..'}
	auto get_assertion = hex::bytes<
		"a2"
		"  01 63 612e62"
		"  02 5820 0000000000000000000000000000000000000000000000000000000000000000"
	>();
	request(CTAP_CMD_GET_ASSERTION, std::vector<uint8_t>(get_assertion.begin(), get_assertion.end()));
	EXPECT_EQ(status, CTAP2_OK);
}

// the weak default policy (a platform may replace it)
bool meets(const char *pin) {
	return ctap_pin_meets_complexity_policy(reinterpret_cast<const uint8_t *>(pin), strlen(pin));
}

TEST(CtapPinComplexityDefault, RefusesRepeatsAndDigitRuns) {
	EXPECT_FALSE(meets("1111"));
	EXPECT_FALSE(meets("aaaa"));
	EXPECT_FALSE(meets("1234"));
	EXPECT_FALSE(meets("987654"));
	EXPECT_TRUE(meets("1357"));
	EXPECT_TRUE(meets("1243"));
	EXPECT_TRUE(meets("ABCD"));
}

} // namespace
