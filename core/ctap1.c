#include <string.h>
#include "ctap1.h"
#include "ctap_asn1.h"
#include "ctap_credentials_store.h"
#include "utils.h"

// FIDO U2F Raw Message Formats v1.2
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html

#define CTAP1_U2F_VERSION "U2F_V2"
#define CTAP1_KEY_HANDLE_SIZE 32 // the credential ID
#define CTAP1_MAX_CERT_SIZE 320

// --- the attestation key and its self-signed certificate

// subject = issuer = CN=LionKey U2F
static const uint8_t cert_name[] = {
	0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b,
	'L', 'i', 'o', 'n', 'K', 'e', 'y', ' ', 'U', '2', 'F',
};
// ecdsa-with-SHA256
static const uint8_t cert_sig_alg[] = {
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
};
// 2026-01-01 00:00:00 .. 2049-12-31 23:59:59 (UTCTime)
static const uint8_t cert_validity[] = {
	0x30, 0x1e,
	0x17, 0x0d, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
	0x17, 0x0d, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z',
};
// SubjectPublicKeyInfo of a P-256 key, followed by 0x04 || x || y
static const uint8_t cert_spki_prefix[] = {
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
};

static void append(uint8_t *out, size_t *pos, const void *data, size_t size) {
	memcpy(&out[*pos], data, size);
	*pos += size;
}

// a DER tag and length (lengths up to 65535)
static void append_header(uint8_t *out, size_t *pos, uint8_t tag, size_t length) {
	out[(*pos)++] = tag;
	if (length < 0x80) {
		out[(*pos)++] = (uint8_t) length;
	} else if (length < 0x100) {
		out[(*pos)++] = 0x81;
		out[(*pos)++] = (uint8_t) length;
	} else {
		out[(*pos)++] = 0x82;
		out[(*pos)++] = (uint8_t) (length >> 8);
		out[(*pos)++] = (uint8_t) length;
	}
}

// ES256 over SHA-256(data), as an ASN.1 DER Ecdsa-Sig-Value (at most 72 bytes)
static uint8_t sign_der(
	const ctap_crypto_t *crypto,
	const uint8_t *private_key,
	const uint8_t *data,
	size_t data_size,
	uint8_t *der,
	size_t *der_size
) {
	uint8_t hash[CTAP_SHA256_HASH_SIZE];
	ctap_crypto_check(crypto->sha256_compute_digest(crypto, data, data_size, hash));
	uint8_t signature[64];
	ctap_crypto_check(crypto->ecc_secp256r1_sign(crypto, private_key, hash, sizeof(hash), signature, NULL));
	ctap_convert_to_asn1_der_ecdsa_sig_value(signature, der, der_size);
	return CTAP2_OK;
}

// a self-signed X.509 v3 certificate (no extensions) for the key
static uint8_t make_certificate(
	const ctap_crypto_t *crypto,
	const uint8_t *private_key,
	const uint8_t *public_key,
	uint8_t *cert,
	size_t *cert_size
) {
	uint8_t ret;
	uint8_t serial[8];
	ctap_crypto_check(crypto->rng_generate_data(crypto, serial, sizeof(serial)));
	serial[0] = (uint8_t) ((serial[0] & 0x3f) | 0x40); // positive, minimal
	static const uint8_t version_v3[] = {0xa0, 0x03, 0x02, 0x01, 0x02};

	const size_t tbs_content_size = sizeof(version_v3) + 2 + sizeof(serial) + sizeof(cert_sig_alg)
		+ sizeof(cert_name) + sizeof(cert_validity) + sizeof(cert_name) + sizeof(cert_spki_prefix) + 64;
	uint8_t tbs[4 + tbs_content_size];
	size_t tbs_size = 0;
	append_header(tbs, &tbs_size, 0x30, tbs_content_size);
	append(tbs, &tbs_size, version_v3, sizeof(version_v3));
	append_header(tbs, &tbs_size, 0x02, sizeof(serial));
	append(tbs, &tbs_size, serial, sizeof(serial));
	append(tbs, &tbs_size, cert_sig_alg, sizeof(cert_sig_alg));
	append(tbs, &tbs_size, cert_name, sizeof(cert_name));
	append(tbs, &tbs_size, cert_validity, sizeof(cert_validity));
	append(tbs, &tbs_size, cert_name, sizeof(cert_name));
	append(tbs, &tbs_size, cert_spki_prefix, sizeof(cert_spki_prefix));
	append(tbs, &tbs_size, public_key, 64);

	uint8_t sig[72];
	size_t sig_size;
	ctap_check(sign_der(crypto, private_key, tbs, tbs_size, sig, &sig_size));

	const size_t cert_content_size = tbs_size + sizeof(cert_sig_alg) + 2 + 1 + sig_size;
	if (4 + cert_content_size > CTAP1_MAX_CERT_SIZE) {
		return CTAP1_ERR_OTHER;
	}
	*cert_size = 0;
	append_header(cert, cert_size, 0x30, cert_content_size);
	append(cert, cert_size, tbs, tbs_size);
	append(cert, cert_size, cert_sig_alg, sizeof(cert_sig_alg));
	append_header(cert, cert_size, 0x03, 1 + sig_size);
	cert[(*cert_size)++] = 0x00; // no unused bits
	append(cert, cert_size, sig, sig_size);
	return CTAP2_OK;
}

// the attestation key (32 bytes) and certificate: found, or made and stored
static uint8_t get_attestation(ctap_state_t *state, const uint8_t **private_key, const uint8_t **cert, size_t *cert_size) {
	const ctap_storage_t *const storage = state->storage;
	const ctap_crypto_t *const crypto = state->crypto;
	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_U2F_ATTESTATION,
	};
	if (storage->find_item(storage, &item) != CTAP_STORAGE_OK || item.size <= 32) {
		uint8_t ret;
		uint8_t data[32 + CTAP1_MAX_CERT_SIZE];
		uint8_t public_key[64];
		// a random 32-byte string is a valid P-256 private key but for a negligible chance
		bool valid = false;
		for (int attempt = 0; attempt < 4 && !valid; ++attempt) {
			ctap_crypto_check(crypto->rng_generate_data(crypto, data, 32));
			valid = crypto->ecc_secp256r1_compute_public_key(crypto, data, public_key) == CTAP_CRYPTO_OK;
		}
		if (!valid) {
			return CTAP1_ERR_OTHER;
		}
		size_t size;
		ctap_check(make_certificate(crypto, data, public_key, &data[32], &size));
		item.handle = 0;
		item.key = CTAP_STORAGE_KEY_U2F_ATTESTATION;
		item.size = 32 + size;
		item.data = data;
		const ctap_storage_status_t status = storage->create_or_update_item(storage, &item);
		memset(data, 0, 32);
		if (status != CTAP_STORAGE_OK) {
			return CTAP2_ERR_KEY_STORE_FULL;
		}
		// the stored copy
		item.handle = 0;
		item.key = CTAP_STORAGE_KEY_U2F_ATTESTATION;
		if (storage->find_item(storage, &item) != CTAP_STORAGE_OK || item.size <= 32) {
			return CTAP1_ERR_OTHER;
		}
	}
	*private_key = item.data;
	*cert = &item.data[32];
	*cert_size = item.size - 32;
	return CTAP2_OK;
}

// --- the commands

static size_t status_word(uint8_t *response, size_t pos, uint16_t sw) {
	response[pos] = (uint8_t) (sw >> 8);
	response[pos + 1] = (uint8_t) sw;
	return pos + 2;
}

static size_t u2f_version(uint8_t *response, size_t data_size) {
	if (data_size != 0) {
		return status_word(response, 0, CTAP1_SW_WRONG_LENGTH);
	}
	memcpy(response, CTAP1_U2F_VERSION, sizeof(CTAP1_U2F_VERSION) - 1);
	return status_word(response, sizeof(CTAP1_U2F_VERSION) - 1, CTAP1_SW_NO_ERROR);
}

static bool user_present(void) {
	return ctap_wait_for_user_presence() == CTAP_UP_RESULT_ALLOW;
}

// request: challenge (32) || application (32)
// response: 0x05 || user public key (65) || L || key handle || attestation certificate || signature
static size_t u2f_register(ctap_state_t *state, const uint8_t *data, size_t data_size, uint8_t *response) {
	if (data_size != 64) {
		return status_word(response, 0, CTAP1_SW_WRONG_LENGTH);
	}
	const uint8_t *const challenge = data;
	const uint8_t *const application = data + 32;
	if (!user_present()) {
		return status_word(response, 0, CTAP1_SW_CONDITIONS_NOT_SATISFIED);
	}
	ctap_send_keepalive_if_needed(CTAP_STATUS_PROCESSING);

	const uint8_t *attestation_key;
	const uint8_t *cert;
	size_t cert_size;
	if (get_attestation(state, &attestation_key, &cert, &cert_size) != CTAP2_OK) {
		return status_word(response, 0, CTAP1_SW_COMMAND_NOT_ALLOWED);
	}

	// no RP ID string: only its hash, the application parameter
	CTAP_rpId rp_id = {
		.id = {.data = (const uint8_t *) "", .size = 0},
	};
	memcpy(rp_id.hash, application, CTAP_SHA256_HASH_SIZE);
	CTAP_userEntity user;
	memset(&user, 0, sizeof(user));
	user.id.data = (const uint8_t *) "u2f";
	user.id.size = 3;
	ctap_set_present(&user, CTAP_userEntity_id);
	ctap_credential_handle_t credential;
	if (ctap_create_credential(
		state->storage, state->crypto, false,
		CTAP_extension_credProtect_1_userVerificationOptional, COSE_ALG_ES256,
		CTAP_CREDENTIAL_SOURCE_CTAP_flags_u2f, &rp_id, &user, &credential
	) != CTAP2_OK) {
		return status_word(response, 0, CTAP1_SW_COMMAND_NOT_ALLOWED);
	}
	uint8_t public_key[64];
	if (ctap_credential_compute_public_key(state->crypto, &credential, public_key) != CTAP2_OK) {
		return status_word(response, 0, CTAP1_SW_COMMAND_NOT_ALLOWED);
	}
	ctap_string_t key_handle;
	ctap_credential_get_id(&credential, &key_handle);

	// signed: 0x00 || application || challenge || key handle || user public key
	uint8_t signed_data[1 + 32 + 32 + CTAP1_KEY_HANDLE_SIZE + 65];
	size_t n = 0;
	signed_data[n++] = 0x00;
	append(signed_data, &n, application, 32);
	append(signed_data, &n, challenge, 32);
	append(signed_data, &n, key_handle.data, key_handle.size);
	signed_data[n++] = 0x04;
	append(signed_data, &n, public_key, 64);
	uint8_t sig[72];
	size_t sig_size;
	if (sign_der(state->crypto, attestation_key, signed_data, n, sig, &sig_size) != CTAP2_OK) {
		return status_word(response, 0, CTAP1_SW_COMMAND_NOT_ALLOWED);
	}

	size_t pos = 0;
	response[pos++] = 0x05; // reserved
	response[pos++] = 0x04; // uncompressed point
	append(response, &pos, public_key, 64);
	response[pos++] = (uint8_t) key_handle.size;
	append(response, &pos, key_handle.data, key_handle.size);
	append(response, &pos, cert, cert_size);
	append(response, &pos, sig, sig_size);
	return status_word(response, pos, CTAP1_SW_NO_ERROR);
}

// request: challenge (32) || application (32) || L || key handle
// response: user presence (1) || counter (4, big-endian) || signature
static size_t u2f_authenticate(
	ctap_state_t *state,
	uint8_t control,
	const uint8_t *data,
	size_t data_size,
	uint8_t *response
) {
	if (data_size < 65 || data_size != 65u + data[64]) {
		return status_word(response, 0, CTAP1_SW_WRONG_LENGTH);
	}
	const uint8_t *const challenge = data;
	const uint8_t *const application = data + 32;
	const CTAP_credDesc desc = {
		.type = CTAP_pubKeyCredType_public_key,
		.id = {.data = data + 65, .size = data[64]},
	};
	ctap_credential_handle_t credential;
	if ((
		!ctap_lookup_credential_by_desc(state->storage, &desc, &credential)
		|| !ctap_credential_matches_rp_id_hash(&credential, application)
		// U2F is ES256 only and has no user verification
		|| ctap_credential_get_alg(&credential) != COSE_ALG_ES256
		|| ctap_credential_get_cred_protect(&credential) == CTAP_extension_credProtect_3_userVerificationRequired
	)) {
		return status_word(response, 0, CTAP1_SW_WRONG_DATA);
	}

	uint8_t flags;
	switch (control) {
		case CTAP1_AUTH_CHECK_ONLY:
			// the key handle is ours and for this application
			return status_word(response, 0, CTAP1_SW_CONDITIONS_NOT_SATISFIED);
		case CTAP1_AUTH_ENFORCE_USER_PRESENCE:
			if (!user_present()) {
				return status_word(response, 0, CTAP1_SW_CONDITIONS_NOT_SATISFIED);
			}
			ctap_send_keepalive_if_needed(CTAP_STATUS_PROCESSING);
			flags = 0x01;
			break;
		case CTAP1_AUTH_DONT_ENFORCE_USER_PRESENCE:
			flags = 0x00;
			break;
		default:
			return status_word(response, 0, CTAP1_SW_WRONG_DATA);
	}

	uint32_t counter;
	if (ctap_increment_global_signature_counter(state->storage, state->crypto, &counter) != CTAP2_OK) {
		return status_word(response, 0, CTAP1_SW_COMMAND_NOT_ALLOWED);
	}
	const uint8_t counter_be[4] = {
		(uint8_t) (counter >> 24), (uint8_t) (counter >> 16), (uint8_t) (counter >> 8), (uint8_t) counter,
	};

	// signed: application || user presence || counter || challenge
	uint8_t signed_data[32 + 1 + 4 + 32];
	size_t n = 0;
	append(signed_data, &n, application, 32);
	signed_data[n++] = flags;
	append(signed_data, &n, counter_be, 4);
	append(signed_data, &n, challenge, 32);
	uint8_t hash[CTAP_SHA256_HASH_SIZE];
	uint8_t raw[64];
	if ((
		state->crypto->sha256_compute_digest(state->crypto, signed_data, n, hash) != CTAP_CRYPTO_OK
		|| ctap_credential_compute_signature(state->crypto, &credential, hash, sizeof(hash), raw) != CTAP2_OK
	)) {
		return status_word(response, 0, CTAP1_SW_COMMAND_NOT_ALLOWED);
	}

	size_t pos = 0;
	response[pos++] = flags;
	append(response, &pos, counter_be, 4);
	size_t sig_size;
	ctap_convert_to_asn1_der_ecdsa_sig_value(raw, &response[pos], &sig_size);
	pos += sig_size;
	return status_word(response, pos, CTAP1_SW_NO_ERROR);
}

size_t ctap1_request(
	ctap_state_t *const state,
	const uint8_t *const apdu,
	const size_t apdu_size,
	uint8_t *const response,
	const size_t response_max_size
) {
	if (response_max_size < CTAP1_MAX_RESPONSE_SIZE) {
		return response_max_size >= 2 ? status_word(response, 0, CTAP1_SW_WRONG_LENGTH) : 0;
	}
	if (apdu_size < 4) {
		return status_word(response, 0, CTAP1_SW_WRONG_LENGTH);
	}
	state->current_time = ctap_get_current_time();

	// CLA INS P1 P2, then (short) [Lc data] [Le] or (extended) [00 Lc(2) data] [Le(2)]
	const uint8_t *data = NULL;
	size_t data_size = 0;
	if (apdu_size == 4 || apdu_size == 5) {
		// no data (5: a short Le)
	} else if (apdu[4] == 0x00 && apdu_size >= 7) {
		data_size = ((size_t) apdu[5] << 8) | apdu[6];
		data = apdu + 7;
		const size_t rest = apdu_size - 7;
		// 00 Le(2) only (extended Le, no data), or data and an optional Le(2)
		if (apdu_size == 7) {
			data_size = 0;
		} else if (rest != data_size && rest != data_size + 2) {
			return status_word(response, 0, CTAP1_SW_WRONG_LENGTH);
		}
	} else {
		data_size = apdu[4];
		data = apdu + 5;
		const size_t rest = apdu_size - 5;
		if (rest != data_size && rest != data_size + 1) {
			return status_word(response, 0, CTAP1_SW_WRONG_LENGTH);
		}
	}

	if (apdu[0] != 0x00) {
		return status_word(response, 0, CTAP1_SW_CLA_NOT_SUPPORTED);
	}
	switch (apdu[1]) {
		case CTAP1_INS_VERSION:
			return u2f_version(response, data_size);
		case CTAP1_INS_REGISTER:
			return u2f_register(state, data, data_size, response);
		case CTAP1_INS_AUTHENTICATE:
			return u2f_authenticate(state, apdu[2], data, data_size, response);
	}
	return status_word(response, 0, CTAP1_SW_INS_NOT_SUPPORTED);
}
