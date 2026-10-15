#ifndef LIONKEY_CTAP1_H
#define LIONKEY_CTAP1_H

#include "ctap.h"

// CTAP1 / U2F raw messages (FIDO U2F Raw Message Formats v1.2, CTAP 2.2 §10 U2F compatibility):
// U2F_REGISTER, U2F_AUTHENTICATE, U2F_VERSION.
//
// A U2F credential is a non-discoverable ES256 credential whose RP ID hash is the U2F application
// parameter (no RP ID string, CTAP_CREDENTIAL_SOURCE_CTAP_flags_u2f); the key handle is its
// 32-byte credential ID. CTAP2 credentials (ES256) work with U2F_AUTHENTICATE too, and U2F ones
// with authenticatorGetAssertion (e.g. the appid extension: rpId = the AppID).
//
// U2F_REGISTER's attestation: a per-authenticator P-256 key and a self-signed X.509 certificate,
// made at the first registration and kept under CTAP_STORAGE_KEY_U2F_ATTESTATION (a reset makes a new one).

#define CTAP1_INS_REGISTER      0x01
#define CTAP1_INS_AUTHENTICATE  0x02
#define CTAP1_INS_VERSION       0x03

// U2F_AUTHENTICATE control byte (P1)
#define CTAP1_AUTH_CHECK_ONLY                 0x07
#define CTAP1_AUTH_ENFORCE_USER_PRESENCE      0x03
#define CTAP1_AUTH_DONT_ENFORCE_USER_PRESENCE 0x08

// ISO 7816 status words
#define CTAP1_SW_NO_ERROR                 0x9000
#define CTAP1_SW_CONDITIONS_NOT_SATISFIED 0x6985
#define CTAP1_SW_WRONG_DATA               0x6A80
#define CTAP1_SW_WRONG_LENGTH             0x6700
#define CTAP1_SW_CLA_NOT_SUPPORTED        0x6E00
#define CTAP1_SW_INS_NOT_SUPPORTED        0x6D00
#define CTAP1_SW_COMMAND_NOT_ALLOWED      0x6986 // e.g. the user did not confirm in time

// the largest response: U2F_REGISTER with the certificate
#define CTAP1_MAX_RESPONSE_SIZE 640

/**
 * Handles one U2F APDU (short or extended length encoding).
 *
 * @param state the CTAP state (ctap_init() done)
 * @param apdu the request: CLA INS P1 P2 [Lc data] [Le]
 * @param response the response data followed by the status word (SW1 SW2)
 * @param response_max_size at least CTAP1_MAX_RESPONSE_SIZE
 * @return the response length (at least 2: the status word)
 */
size_t ctap1_request(
	ctap_state_t *state,
	const uint8_t *apdu,
	size_t apdu_size,
	uint8_t *response,
	size_t response_max_size
);

#endif // LIONKEY_CTAP1_H
