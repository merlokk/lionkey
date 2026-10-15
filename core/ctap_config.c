#include <string.h>
#include "ctap.h"
#include "utils.h"

// 6.11. authenticatorConfig (0x0D)
// https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorConfig

void ctap_init_config_persistent_state(ctap_state_t *const state) {

	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CONFIG,
	};

	const ctap_storage_t *const storage = state->storage;

	if (storage->find_item(storage, &item) == CTAP_STORAGE_OK) {
		if (item.size == sizeof(state->config_state)) {
			state->config_state_item_handle = item.handle;
			memcpy(&state->config_state, item.data, sizeof(state->config_state));
			debug_log("initialized config_state from the storage" nl);
			return;
		}
		error_log(red("ignoring invalid config_state in the storage") nl);
	}

	memset(&state->config_state, 0, sizeof(state->config_state));
	state->config_state_item_handle = 0u;

}

bool ctap_update_config_persistent_state(ctap_state_t *const state) {
	const ctap_storage_t *const storage = state->storage;
	ctap_storage_item_t item = {
		.handle = state->config_state_item_handle,
		.key = CTAP_STORAGE_KEY_CONFIG,
		.size = sizeof(state->config_state),
		.data = (const uint8_t *) &state->config_state,
	};
	if (storage->create_or_update_item(storage, &item) != CTAP_STORAGE_OK) {
		error_log(red("creating or updating config_state in the storage failed") nl);
		return false;
	}
	state->config_state_item_handle = item.handle;
	return true;
}

uint32_t ctap_get_long_touch_for_reset_ms(const ctap_state_t *const state) {
	if (state->long_touch_for_reset_ms != 0u) {
		return state->long_touch_for_reset_ms;
	}
	return (state->config_state.flags & CTAP_CONFIG_flags_long_touch_for_reset) != 0u
		? CTAP_LONG_TOUCH_FOR_RESET_MS
		: 0u;
}

// sets or clears flags and persists them; CTAP1_ERR_OTHER on a storage error
static uint8_t set_config_flags(ctap_state_t *const state, const uint8_t set, const uint8_t clear) {
	const ctap_config_persistent_state_t previous = state->config_state;
	state->config_state.flags = (uint8_t) ((state->config_state.flags | set) & ~clear);
	if (state->config_state.flags == previous.flags) {
		return CTAP2_OK;
	}
	if (!ctap_update_config_persistent_state(state)) {
		state->config_state = previous;
		return CTAP1_ERR_OTHER;
	}
	return CTAP2_OK;
}

static uint8_t verify_config_params(
	ctap_state_t *const state,
	const CTAP_authenticatorConfig *const cfg,
	ctap_pin_protocol_t *const pin_protocol
) {
	// 4.4. verify(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams, pinUvAuthParam)
	uint8_t verify_ctx[pin_protocol->verify_get_context_size(pin_protocol)];
	if (pin_protocol->verify_init_with_pin_uv_auth_token(
		pin_protocol,
		&verify_ctx,
		&state->pin_uv_auth_token_state
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	uint8_t prefix[32 + 1 + 1];
	memset(prefix, 0xff, 32);
	prefix[32] = CTAP_CMD_CONFIG;
	prefix[33] = cfg->subCommand;
	pin_protocol->verify_update(pin_protocol, &verify_ctx, prefix, sizeof(prefix));
	if (cfg->subCommandParams.raw_size > 0) {
		pin_protocol->verify_update(
			pin_protocol,
			&verify_ctx,
			cfg->subCommandParams.raw, cfg->subCommandParams.raw_size
		);
	}
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		cfg->pinUvAuthParam.data, cfg->pinUvAuthParam.size
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	// 4.5. If the pinUvAuthToken does not have the acfg permission, return CTAP2_ERR_PIN_AUTH_INVALID.
	if (!ctap_pin_uv_auth_token_has_permissions(state, CTAP_clientPIN_pinUvAuthToken_permission_acfg)) {
		debug_log(red("pinUvAuthToken does not have the acfg permission") nl);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	return CTAP2_OK;
}

// 6.11.2. Toggle Always Require User Verification
static uint8_t config_toggle_always_uv(ctap_state_t *const state) {
	// We support disabling it again (the spec: authenticators SHOULD).
	// makeCredUvNotRqd follows alwaysUv (see ctap_get_info()), nothing else to reset.
	if (ctap_is_always_uv(state)) {
		return set_config_flags(state, 0u, CTAP_CONFIG_flags_always_uv);
	}
	return set_config_flags(state, CTAP_CONFIG_flags_always_uv, 0u);
}

// 6.11.4. Setting a minimum PIN Length
static uint8_t config_set_min_pin_length(ctap_state_t *const state, const CTAP_authenticatorConfig *const cfg) {

	const CTAP_authenticatorConfig_subCmdParams *const params = &cfg->subCommandParams;
	const bool params_present = ctap_param_is_present(cfg, CTAP_authenticatorConfig_subCommandParams);
	const uint8_t current_min = ctap_get_pin_min_code_point_length(state);

	// 1. If newMinPINLength is absent, then let newMinPINLength be present with the current minimum PIN length.
	const uint8_t new_min = (
		params_present && ctap_param_is_present(params, CTAP_authenticatorConfig_setMinPINLength_newMinPINLength)
	) ? params->newMinPINLength : current_min;

	// 2. If minPinLengthRPIDs is present and the minPinLength extension is not supported,
	//    return CTAP1_ERR_INVALID_PARAMETER. (It is supported.)
	const bool rp_ids_present = params_present
		&& ctap_param_is_present(params, CTAP_authenticatorConfig_setMinPINLength_minPinLengthRPIDs)
		&& params->minPinLengthRPIDs_length > 0;

	// 8.1. If the list is longer than maxRPIDsForSetMinPINLength, return an error
	//      (no code given; checked first so that a refused request changes nothing).
	if (rp_ids_present && params->minPinLengthRPIDs_length > CTAP_MAX_MIN_PIN_LENGTH_RP_IDS) {
		return CTAP2_ERR_KEY_STORE_FULL;
	}

	// 3. If newMinPINLength < current minimum PIN length, return CTAP2_ERR_PIN_POLICY_VIOLATION.
	//    Also above the maximum PIN length (63 bytes, so at most 63 code points): no PIN could satisfy it.
	if (new_min < current_min || new_min > 63) {
		return CTAP2_ERR_PIN_POLICY_VIOLATION;
	}

	const bool force_change_pin = params_present
		&& ctap_param_is_present(params, CTAP_authenticatorConfig_setMinPINLength_forceChangePin)
		&& params->forceChangePin;

	// 4. If forceChangePin is true and no PIN is set, return CTAP2_ERR_PIN_NOT_SET.
	if (force_change_pin && !ctap_is_pin_set(state)) {
		return CTAP2_ERR_PIN_NOT_SET;
	}

	// 5. If pinComplexityPolicy is true, set pinComplexityPolicy to true in getInfo
	//    (until a reset; applied with the other changes below).
	const bool enable_pin_complexity_policy = params_present
		&& ctap_param_is_present(params, CTAP_authenticatorConfig_setMinPINLength_pinComplexityPolicy)
		&& params->pinComplexityPolicy;

	// 6. If a PIN is set and PINCodePointLength < newMinPINLength, set forcePINChange.
	const bool force = force_change_pin
		|| (ctap_is_pin_set(state) && state->pin_state.pin_code_point_length < new_min);

	// persist the new minimum
	if (new_min != current_min) {
		state->pin_state.pin_min_code_point_length = new_min;
		ctap_update_pin_persistent_state(state);
	}

	if (enable_pin_complexity_policy) {
		uint8_t ret;
		ctap_check(set_config_flags(state, CTAP_CONFIG_flags_pin_complexity_policy, 0u));
	}

	if (force) {
		uint8_t ret;
		ctap_check(set_config_flags(state, CTAP_CONFIG_flags_force_pin_change, 0u));
		// 7. resetPersistentPinUvAuthToken() (not applicable) and
		//    resetPinUvAuthToken() for all pinUvAuthProtocols supported by this authenticator.
		ctap_all_pin_protocols_reset_pin_uv_auth_token(state);
	}

	// 8. If minPinLengthRPIDs is present and contains at least one string:
	//    2. + 3. no pre-configured list: the given list replaces the previously added one.
	//    4. If it cannot be stored, return CTAP2_ERR_KEY_STORE_FULL.
	if (rp_ids_present) {
		uint8_t hashes[CTAP_MAX_MIN_PIN_LENGTH_RP_IDS][CTAP_SHA256_HASH_SIZE];
		const size_t count = params->minPinLengthRPIDs_length;
		for (size_t i = 0; i < count; ++i) {
			const ctap_string_t *const rp_id = &params->minPinLengthRPIDs[i];
			ctap_crypto_check(state->crypto->sha256_compute_digest(
				state->crypto, rp_id->data, rp_id->size, hashes[i]
			));
		}
		ctap_storage_item_t item = {
			.key = CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS,
		};
		const ctap_storage_t *const storage = state->storage;
		item.handle = storage->find_item(storage, &item) == CTAP_STORAGE_OK ? item.handle : 0u;
		item.key = CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS;
		item.size = count * CTAP_SHA256_HASH_SIZE;
		item.data = &hashes[0][0];
		if (storage->create_or_update_item(storage, &item) != CTAP_STORAGE_OK) {
			return CTAP2_ERR_KEY_STORE_FULL;
		}
	}

	return CTAP2_OK;

}

bool ctap_min_pin_length_rp_id_allowed(const ctap_state_t *const state, const uint8_t *const rp_id_hash) {
	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS,
	};
	const ctap_storage_t *const storage = state->storage;
	if (storage->find_item(storage, &item) != CTAP_STORAGE_OK) {
		return false;
	}
	for (size_t offset = 0; offset + CTAP_SHA256_HASH_SIZE <= item.size; offset += CTAP_SHA256_HASH_SIZE) {
		if (memcmp(&item.data[offset], rp_id_hash, CTAP_SHA256_HASH_SIZE) == 0) {
			return true;
		}
	}
	return false;
}

size_t ctap_min_pin_length_rp_ids_count(const ctap_state_t *const state) {
	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS,
	};
	const ctap_storage_t *const storage = state->storage;
	if (storage->find_item(storage, &item) != CTAP_STORAGE_OK) {
		return 0;
	}
	return item.size / CTAP_SHA256_HASH_SIZE;
}

// CTAP 2.3: enableLongTouchForReset
static uint8_t config_enable_long_touch_for_reset(ctap_state_t *const state) {
	return set_config_flags(state, CTAP_CONFIG_flags_long_touch_for_reset, 0u);
}

uint8_t ctap_config(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	lion_unused(encoder); // no subcommand returns data

	uint8_t ret;

	CTAP_authenticatorConfig cfg;
	// 1. If subCommand is absent, return CTAP2_ERR_MISSING_PARAMETER.
	ctap_check(ctap_parse_config(it, &cfg));

	// 2. If the subcommand is not supported, return CTAP1_ERR_INVALID_PARAMETER.
	//    (enableEnterpriseAttestation: no enterprise attestation; vendorPrototype: none defined)
	switch (cfg.subCommand) {
		case CTAP_authenticatorConfig_subCmd_toggleAlwaysUv:
		case CTAP_authenticatorConfig_subCmd_setMinPINLength:
		case CTAP_authenticatorConfig_subCmd_enableLongTouchForReset:
			break;
		default:
			return CTAP1_ERR_INVALID_PARAMETER;
	}

	const bool protected_by_uv = ctap_is_pin_set(state);

	// 3. toggleAlwaysUv on an authenticator not protected by any form of user verification
	//    while alwaysUv is true: go to Step 5 (lets the initial setup turn it off).
	const bool skip_auth = cfg.subCommand == CTAP_authenticatorConfig_subCmd_toggleAlwaysUv
		&& !protected_by_uv
		&& ctap_is_always_uv(state);

	// 4. If the authenticator is protected by some form of user verification, or alwaysUv is true:
	if (!skip_auth && (protected_by_uv || ctap_is_always_uv(state))) {
		// 4.1. If pinUvAuthParam is absent, return CTAP2_ERR_PUAT_REQUIRED.
		if (!ctap_param_is_present(&cfg, CTAP_authenticatorConfig_pinUvAuthParam)) {
			return CTAP2_ERR_PUAT_REQUIRED;
		}
		// 4.2. If pinUvAuthProtocol is absent, return CTAP2_ERR_MISSING_PARAMETER.
		if (!ctap_param_is_present(&cfg, CTAP_authenticatorConfig_pinUvAuthProtocol)) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		// 4.3. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
		ctap_pin_protocol_t *pin_protocol;
		ctap_check(ctap_get_pin_protocol(state, cfg.pinUvAuthProtocol, &pin_protocol));
		// 4.4. + 4.5.
		ctap_check(verify_config_params(state, &cfg, pin_protocol));
	}

	// 5. + 6.
	switch (cfg.subCommand) {
		case CTAP_authenticatorConfig_subCmd_toggleAlwaysUv:
			debug_log(magenta("CTAP_authenticatorConfig_subCmd_toggleAlwaysUv") nl);
			return config_toggle_always_uv(state);
		case CTAP_authenticatorConfig_subCmd_setMinPINLength:
			debug_log(magenta("CTAP_authenticatorConfig_subCmd_setMinPINLength") nl);
			return config_set_min_pin_length(state, &cfg);
		case CTAP_authenticatorConfig_subCmd_enableLongTouchForReset:
			debug_log(magenta("CTAP_authenticatorConfig_subCmd_enableLongTouchForReset") nl);
			return config_enable_long_touch_for_reset(state);
	}

	// should never be reached (see Step 2)
	return CTAP1_ERR_INVALID_PARAMETER;

}
