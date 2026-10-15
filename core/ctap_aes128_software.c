// AES-128-CBC for getInfo's encIdentifier and encCredStoreState (CTAP 2.2), next to the AES-256
// build of tiny-AES that the rest uses: the same source, compiled here for 128-bit keys
// under other names.

#undef TINYAES_ENABLE_AES256
#undef TINYAES_ENABLE_AES192
#define AES_init_ctx lk_aes128_init_ctx
#define AES_init_ctx_iv lk_aes128_init_ctx_iv
#define AES_ctx_set_iv lk_aes128_ctx_set_iv
#define AES_ECB_encrypt lk_aes128_ECB_encrypt
#define AES_ECB_decrypt lk_aes128_ECB_decrypt
#define AES_CBC_encrypt_buffer lk_aes128_CBC_encrypt_buffer
#define AES_CBC_decrypt_buffer lk_aes128_CBC_decrypt_buffer
#define AES_CTR_xcrypt_buffer lk_aes128_CTR_xcrypt_buffer
#define AES_ctx lk_aes128_ctx

#include "aes.c"

#include "ctap_crypto_software.h"

_Static_assert(TINYAES_AES_KEYLEN == 16, "AES-128");

ctap_crypto_status_t ctap_software_crypto_aes_128_cbc_encrypt(
	const ctap_crypto_t *const crypto,
	const uint8_t *const iv,
	const uint8_t *const key,
	uint8_t *const data,
	const size_t data_length
) {
	(void) crypto;
	if (data_length % TINYAES_AES_BLOCKLEN != 0) {
		return CTAP_CRYPTO_ERROR;
	}
	struct lk_aes128_ctx ctx;
	lk_aes128_init_ctx_iv(&ctx, key, iv);
	lk_aes128_CBC_encrypt_buffer(&ctx, data, data_length);
	memset(&ctx, 0, sizeof(ctx));
	return CTAP_CRYPTO_OK;
}
