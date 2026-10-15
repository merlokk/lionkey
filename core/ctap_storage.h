#ifndef LIONKEY_CTAP_STORAGE_H
#define LIONKEY_CTAP_STORAGE_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include "compiler.h"

typedef enum ctap_storage_key {
	CTAP_STORAGE_KEY_PIN_INFO = 1,
	CTAP_STORAGE_KEY_CREDENTIAL = 2,
	CTAP_STORAGE_KEY_GLOBAL_SIGNATURE_COUNTER = 3,
	CTAP_STORAGE_KEY_CONFIG = 4,
	// minPinLength extension: SHA-256 of each RP ID allowed to read the minimum PIN length
	CTAP_STORAGE_KEY_MIN_PIN_LENGTH_RP_IDS = 5,
	// U2F_REGISTER attestation: the private key (32 bytes) and its self-signed certificate (DER)
	CTAP_STORAGE_KEY_U2F_ATTESTATION = 6,
	// the persistentPinUvAuthTokens (one per PIN/UV auth protocol) and their permissions
	CTAP_STORAGE_KEY_PERSISTENT_PUAT = 7,
	// getInfo encIdentifier: the 128-bit device identifier (random, a reset makes a new one)
	CTAP_STORAGE_KEY_DEVICE_IDENTIFIER = 8,
} ctap_storage_key_t;

typedef enum ctap_storage_status {
	CTAP_STORAGE_OK = 0,
	CTAP_STORAGE_ERROR = 1,
	CTAP_STORAGE_OUT_OF_MEMORY_ERROR = 2,
	CTAP_STORAGE_ITEM_NOT_FOUND = 3,
} ctap_storage_status_t;

typedef struct ctap_storage_item {
	uint32_t handle;
	uint32_t key;
	size_t size;
	const uint8_t *data;
} ctap_storage_item_t;

typedef struct ctap_storage {

	void *context;

	ctap_storage_status_t (*init)(
		const struct ctap_storage *storage
	);

	ctap_storage_status_t (*find_item)(
		const struct ctap_storage *storage,
		ctap_storage_item_t *item
	);

	ctap_storage_status_t (*create_or_update_item)(
		const struct ctap_storage *storage,
		ctap_storage_item_t *item
	);

	ctap_storage_status_t (*delete_item)(
		const struct ctap_storage *storage,
		uint32_t item_handle
	);

	ctap_storage_status_t (*increment_counter)(
		const struct ctap_storage *storage,
		uint32_t increment,
		uint32_t *counter_new_value
	);

	size_t (*estimate_num_remaining_items)(
		const struct ctap_storage *storage,
		const ctap_storage_item_t *item
	);

	ctap_storage_status_t (*erase)(
		const struct ctap_storage *storage
	);

} ctap_storage_t;

#endif // LIONKEY_CTAP_STORAGE_H
