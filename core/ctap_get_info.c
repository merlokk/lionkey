#include <string.h>
#include "ctap.h"
#include "ctap_credentials_store.h"
#include <hkdf.h>

bool ctap_ensure_device_identifier(ctap_state_t *const state) {
	const ctap_storage_t *const storage = state->storage;
	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_DEVICE_IDENTIFIER,
	};
	if (storage->find_item(storage, &item) == CTAP_STORAGE_OK && item.size == 16) {
		return true;
	}
	uint8_t identifier[16];
	if (state->crypto->rng_generate_data(state->crypto, identifier, sizeof(identifier)) != CTAP_CRYPTO_OK) {
		return false;
	}
	item.handle = 0;
	item.key = CTAP_STORAGE_KEY_DEVICE_IDENTIFIER;
	item.size = sizeof(identifier);
	item.data = identifier;
	return storage->create_or_update_item(storage, &item) == CTAP_STORAGE_OK;
}

// the device identifier (16 bytes); false: none
static bool get_device_identifier(const ctap_state_t *const state, uint8_t *identifier) {
	const ctap_storage_t *const storage = state->storage;
	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_DEVICE_IDENTIFIER,
	};
	if (storage->find_item(storage, &item) != CTAP_STORAGE_OK || item.size != 16) {
		return false;
	}
	memcpy(identifier, item.data, 16);
	return true;
}

// The credential store state: LEFT(SHA-256 over every stored credential, 16). Changes whenever a
// credential is created, deleted or updated; the same otherwise (nothing extra stored).
static bool get_credential_store_state(const ctap_state_t *const state, uint8_t *store_state) {
	const ctap_crypto_t *const crypto = state->crypto;
	const hash_alg_t *const sha256 = crypto->sha256;
	uint8_t sha256_ctx[sha256->ctx_size];
	crypto->sha256_bind_ctx(crypto, sha256_ctx);
	sha256->init(sha256_ctx);
	const ctap_storage_t *const storage = state->storage;
	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
	};
	while (storage->find_item(storage, &item) == CTAP_STORAGE_OK) {
		sha256->update(sha256_ctx, item.data, item.size);
	}
	uint8_t hash[CTAP_SHA256_HASH_SIZE];
	sha256->final(sha256_ctx, hash);
	memcpy(store_state, hash, 16);
	return true;
}

// CTAP 2.2 getInfo encIdentifier / encCredStoreState:
// iv || AES-128-CBC(HKDF-SHA-256(salt = 32 zero bytes, IKM = persistentPinUvAuthToken, L = 16, info), iv, plaintext)
static uint8_t encrypt_get_info_member(
	ctap_state_t *const state,
	const char *const info,
	const uint8_t *const plaintext,
	uint8_t *const out
) {
	const ctap_crypto_t *const crypto = state->crypto;
	const hash_alg_t *const sha256 = crypto->sha256;
	uint8_t sha256_ctx[sha256->ctx_size];
	crypto->sha256_bind_ctx(crypto, sha256_ctx);
	static const uint8_t zero_salt[32] = {0};
	uint8_t key[16];
	hkdf(
		sha256, sha256_ctx,
		zero_salt, sizeof(zero_salt),
		state->pin_protocols[0].persistent_pin_uv_auth_token, CTAP_PIN_UV_AUTH_TOKEN_SIZE,
		(const uint8_t *) info, strlen(info),
		sizeof(key), key
	);
	ctap_crypto_check(crypto->rng_generate_data(crypto, out, 16)); // a fresh iv for every getInfo
	memcpy(&out[16], plaintext, 16);
	const ctap_crypto_status_t status = crypto->aes_128_cbc_encrypt(crypto, out, key, &out[16], 16);
	memset(key, 0, sizeof(key));
	return status == CTAP_CRYPTO_OK ? CTAP2_OK : CTAP1_ERR_OTHER;
}

// in the order of preference (getInfo algorithms); the EdDSA ones only with Ed25519 in the crypto table
static const COSEAlgorithmIdentifier ctap_supported_pub_key_cred_alg[] = {
	COSE_ALG_ES256,
	COSE_ALG_EdDSA,
	COSE_ALG_Ed25519,
};
static const size_t ctap_supported_pub_key_cred_alg_count =
	sizeof(ctap_supported_pub_key_cred_alg) / sizeof(COSEAlgorithmIdentifier);

static bool alg_available(const COSEAlgorithmIdentifier alg, const bool eddsa_supported) {
	return alg == COSE_ALG_ES256 || eddsa_supported;
}

bool ctap_is_supported_pub_key_cred_alg(const CTAP_credParams *cred_params, const bool eddsa_supported) {
	if (cred_params->type != CTAP_pubKeyCredType_public_key) {
		return false;
	}
	for (size_t i = 0; i < ctap_supported_pub_key_cred_alg_count; ++i) {
		if (ctap_supported_pub_key_cred_alg[i] == cred_params->alg) {
			return alg_available(cred_params->alg, eddsa_supported);
		}
	}
	return false;
}

bool ctap_crypto_supports_eddsa(const ctap_crypto_t *const crypto) {
	return crypto->ed25519_compute_public_key != NULL && crypto->ed25519_sign != NULL;
}

const uint8_t ctap_aaguid[CTAP_AAGUID_SIZE] = "\xa8\xa1\x47\x32\x6b\x7d\x12\x0d\xfb\x91\x73\x56\xbc\x18\x98\x03";

uint8_t ctap_get_info(ctap_state_t *state, CborValue *it, CborEncoder *encoder) {

	// This command does not take any parameters.
	lion_unused(it);

	CborEncoder map;
	CborError err;

	// see 6.4. authenticatorGetInfo (0x04)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo

	// start response map
	// 10 members + forcePINChange, maxRPIDsForSetMinPINLength, longTouchForReset, pinComplexityPolicy,
	// (pinComplexityPolicyURL), authenticatorConfigCommands
	const bool pin_complexity_policy = ctap_is_pin_complexity_policy(state);
	const bool pin_complexity_policy_url = state->pin_complexity_policy_url != NULL;
	// encIdentifier and encCredStoreState: only with a persistentPinUvAuthToken to encrypt them with
	uint8_t enc_identifier[32];
	uint8_t enc_cred_store_state[32];
	bool encrypted_members = false;
	if (state->persistent_pin_uv_auth_tokens_ready && state->crypto->aes_128_cbc_encrypt != NULL) {
		uint8_t plaintext[16];
		uint8_t ret;
		if (get_device_identifier(state, plaintext)) {
			ctap_check(encrypt_get_info_member(state, "encIdentifier", plaintext, enc_identifier));
			get_credential_store_state(state, plaintext);
			ctap_check(encrypt_get_info_member(state, "encCredStoreState", plaintext, enc_cred_store_state));
			encrypted_members = true;
		}
		memset(plaintext, 0, sizeof(plaintext));
	}
	cbor_encoding_check(cbor_encoder_create_map(
		encoder,
		&map,
		16 + (pin_complexity_policy_url ? 1 : 0) + (encrypted_members ? 2 : 0)
	));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_versions));
	{
		CborEncoder array;
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, 2));
		cbor_encoding_check(cbor_encode_text_string(&array, "FIDO_2_0", 8));
		cbor_encoding_check(cbor_encode_text_string(&array, "FIDO_2_1", 8));
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_extensions));
	{
		CborEncoder array;
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, 4 + (pin_complexity_policy ? 1 : 0)));
		cbor_encoding_check(cbor_encode_text_string(&array, "credProtect", 11));
		cbor_encoding_check(cbor_encode_text_string(&array, "hmac-secret", 11));
		cbor_encoding_check(cbor_encode_text_string(&array, "hmac-secret-mc", 14));
		cbor_encoding_check(cbor_encode_text_string(&array, "minPinLength", 12));
		// MUST be listed while the PIN complexity policy is enabled
		if (pin_complexity_policy) {
			cbor_encoding_check(cbor_encode_text_string(&array, "pinComplexityPolicy", 19));
		}
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_aaguid));
	cbor_encoding_check(cbor_encode_byte_string(&map, ctap_aaguid, sizeof(ctap_aaguid)));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_options));
	{
		CborEncoder options;
		cbor_encoding_check(cbor_encoder_create_map(&map, &options, 11));

		// keys in the CTAP2 canonical CBOR order: shorter first, then bytewise

		// this authenticator can create discoverable credentials (not default, must be specified)
		cbor_encoding_check(cbor_encode_text_string(&options, "rk", 2));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// capable of testing user presence (this is the default, so we could omit it)
		cbor_encoding_check(cbor_encode_text_string(&options, "up", 2));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// not attached to platform (this is the default, so we could omit it)
		cbor_encoding_check(cbor_encode_text_string(&options, "plat", 4));
		cbor_encoding_check(cbor_encode_boolean(&options, false));

		// the Always Require User Verification feature is supported; true = enabled (toggleAlwaysUv)
		cbor_encoding_check(cbor_encode_text_string(&options, "alwaysUv", 8));
		cbor_encoding_check(cbor_encode_boolean(&options, ctap_is_always_uv(state)));

		// present and set to true -> the authenticatorCredentialManagement command is supported
		cbor_encoding_check(cbor_encode_text_string(&options, "credMgmt", 8));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// present and true -> the authenticatorConfig command is supported
		cbor_encoding_check(cbor_encode_text_string(&options, "authnrCfg", 9));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// If present, it indicates that the device is capable of accepting a PIN from the client
		// ->  if true, it indicates that PIN has been set
		// -> if false, it indicates that PIN has not been set yet
		cbor_encoding_check(cbor_encode_text_string(&options, "clientPin", 9));
		cbor_encoding_check(cbor_encode_boolean(&options, ctap_is_pin_set(state)));

		// CTAP 2.2: the pcmr permission (persistentPinUvAuthToken, read-only credential management)
		cbor_encoding_check(cbor_encode_text_string(&options, "perCredMgmtRO", 13));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		cbor_encoding_check(cbor_encode_text_string(&options, "pinUvAuthToken", 14));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// the setMinPINLength subcommand is supported (only with clientPin present, which it always is)
		cbor_encoding_check(cbor_encode_text_string(&options, "setMinPINLength", 15));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// MUST be false when alwaysUv is present and true
		cbor_encoding_check(cbor_encode_text_string(&options, "makeCredUvNotRqd", 16));
		cbor_encoding_check(cbor_encode_boolean(&options, !ctap_is_always_uv(state)));

		cbor_encoding_check(cbor_encoder_close_container(&map, &options));
	}

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxMsgSize));
	cbor_encoding_check(cbor_encode_uint(&map, 1200)); // TODO

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_pinUvAuthProtocols));
	{
		CborEncoder array;
		const size_t num_protocol_versions = sizeof(state->pin_protocols) / sizeof(ctap_pin_protocol_t);
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, num_protocol_versions));
		// List of supported PIN/UV auth protocols
		// in order of decreasing authenticator preference.
		// MUST NOT contain duplicate values nor be empty if present.
		for (size_t protocol_version = num_protocol_versions; protocol_version >= 1; --protocol_version) {
			cbor_encoding_check(cbor_encode_uint(&array, protocol_version));
		}
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	// maxCredentialCountInList (0x07) specifies the maximum number of credentials supported
	// in a PublicKeyCredentialDescriptor list (authenticatorMakeCredential's excludeList
	// and authenticatorGetAssertion's allowList) at a time by the authenticator.
	// MUST be greater than zero if present.
	// Observed behavior:
	//   When maxCredentialCountInList is not present, Google Chrome defaults to 1.
	//   Our implementation supports an unlimited (*) number of credentials in excludeList and allowList.
	//   (*) = the number is limited by the maximum CTAP CBOR size. In case of the CTAPHID transport
	//   (when CTAPHID_PACKET_SIZE == 64), the maximum CTAP CBOR size is 7608 (= CTAPHID_MAX_PAYLOAD_LENGTH - 1)
	//   (the -1 for the one byte for the CTAP command code).
	//   Therefore, we set a sufficiently high number (which will effectively work as "unlimited")
	//   as the maxCredentialCountInList value.
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxCredentialCountInList));
	cbor_encoding_check(cbor_encode_uint(&map, 128));

	// Maximum Credential ID Length supported by the authenticator. MUST be greater than zero if present.
	// See Credential ID definition in WebAuthn spec at https://w3c.github.io/webauthn/#credential-id
	//   Note that the WebAuthn spec implies that every Credential ID
	//   is at least 16 bytes long and at most 1023 bytes long.
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxCredentialIdLength));
	cbor_encoding_check(cbor_encode_uint(&map, 128)); // TODO: update once we design our Credential ID format

	// The algorithms field is optional, but it is better to include it,
	// so that the clients can use this information to avoid sending
	// such an authenticatorMakeCredential command that would otherwise
	// result in a CTAP2_ERR_UNSUPPORTED_ALGORITHM error
	// (see ctap_parse_make_credential_pub_key_cred_params()).
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_algorithms));
	{
		CborEncoder array;
		const bool eddsa_supported = ctap_crypto_supports_eddsa(state->crypto);
		size_t count = 0;
		for (size_t i = 0; i < ctap_supported_pub_key_cred_alg_count; ++i) {
			count += alg_available(ctap_supported_pub_key_cred_alg[i], eddsa_supported) ? 1 : 0;
		}
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, count));
		for (size_t i = 0; i < ctap_supported_pub_key_cred_alg_count; ++i) {
			const COSEAlgorithmIdentifier alg = ctap_supported_pub_key_cred_alg[i];
			if (!alg_available(alg, eddsa_supported)) {
				continue;
			}
			CborEncoder pub_key_cred_param;
			cbor_encoding_check(cbor_encoder_create_map(&array, &pub_key_cred_param, 2));
			cbor_encoding_check(cbor_encode_text_string(&pub_key_cred_param, "alg", 3));
			cbor_encoding_check(cbor_encode_int(&pub_key_cred_param, alg));
			cbor_encoding_check(cbor_encode_text_string(&pub_key_cred_param, "type", 4));
			cbor_encoding_check(cbor_encode_text_string(&pub_key_cred_param, "public-key", 10));
			cbor_encoding_check(cbor_encoder_close_container(&array, &pub_key_cred_param));
		}
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	// This specifies the current minimum PIN length, in Unicode code points,
	// the authenticator enforces for ClientPIN.
	// This is applicable for ClientPIN only:
	//   the minPINLength member MUST be absent if the clientPin option ID is absent;
	//   it MUST be present if the authenticator supports authenticatorClientPIN (LionKey's case).
	// forcePINChange (0x0C): true -> getPinToken and getPinUvAuthTokenUsingPinWithPermissions
	// return errors until after a successful PIN change
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_forcePINChange));
	cbor_encoding_check(cbor_encode_boolean(&map, ctap_is_force_pin_change(state)));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_minPINLength));
	cbor_encoding_check(cbor_encode_uint(&map, ctap_get_pin_min_code_point_length(state)));

	// maxRPIDsForSetMinPINLength (0x10): MUST be present iff setMinPINLength is supported
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxRPIDsForSetMinPINLength));
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_MAX_MIN_PIN_LENGTH_RP_IDS));

	// attestationFormats (0x16, CTAP 2.2): "none" is implied and MUST NOT be listed
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_attestationFormats));
	{
		CborEncoder array;
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, 1));
		cbor_encoding_check(cbor_encode_text_string(&array, "packed", 6));
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	// longTouchForReset (0x18, CTAP 2.3): present = supported (enableLongTouchForReset),
	// true = authenticatorReset takes a sustained touch (see ctap_reset())
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_longTouchForReset));
	cbor_encoding_check(cbor_encode_boolean(&map, ctap_get_long_touch_for_reset_ms(state) != 0u));

	// encIdentifier (0x19, CTAP 2.2): the device identifier, readable with the persistentPinUvAuthToken
	if (encrypted_members) {
		cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_encIdentifier));
		cbor_encoding_check(cbor_encode_byte_string(&map, enc_identifier, sizeof(enc_identifier)));
	}

	// pinComplexityPolicy (0x1B): whether an additional PIN complexity policy is enforced
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_pinComplexityPolicy));
	cbor_encoding_check(cbor_encode_boolean(&map, pin_complexity_policy));

	// pinComplexityPolicyURL (0x1C): more information about the policy for the user
	if (pin_complexity_policy_url) {
		cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_pinComplexityPolicyURL));
		cbor_encoding_check(cbor_encode_byte_string(
			&map,
			(const uint8_t *) state->pin_complexity_policy_url,
			strlen(state->pin_complexity_policy_url)
		));
	}

	// encCredStoreState (0x1E, CTAP 2.2): changes with every credential change
	if (encrypted_members) {
		cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_encCredStoreState));
		cbor_encoding_check(cbor_encode_byte_string(&map, enc_cred_store_state, sizeof(enc_cred_store_state)));
	}

	// authenticatorConfigCommands (0x1F, CTAP 2.3): the supported authenticatorConfig subcommands
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_authenticatorConfigCommands));
	{
		CborEncoder array;
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, 3));
		cbor_encoding_check(cbor_encode_uint(&array, CTAP_authenticatorConfig_subCmd_toggleAlwaysUv));
		cbor_encoding_check(cbor_encode_uint(&array, CTAP_authenticatorConfig_subCmd_setMinPINLength));
		cbor_encoding_check(cbor_encode_uint(&array, CTAP_authenticatorConfig_subCmd_enableLongTouchForReset));
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}
