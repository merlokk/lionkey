#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
#include <string>
#include <vector>
extern "C" {
#include <ctap.h>
#include <ctap1.h>
#include <ctap_crypto_software.h>
#include <ctap_memory_storage.h>
#include <ctap_test.h>
#include <sha256.h>
#include <uECC.h>
}
namespace {

using bytes = std::vector<uint8_t>;

bytes sha256(const bytes &data) {
	const hash_alg_t *const alg = &hash_alg_sha256;
	std::vector<uint8_t> ctx(alg->ctx_size);
	bytes out(32);
	alg->init(ctx.data());
	alg->update(ctx.data(), data.data(), data.size());
	alg->final(ctx.data(), out.data());
	return out;
}

bytes sha256(const std::string &text) {
	return sha256(bytes(text.begin(), text.end()));
}

// an ASN.1 DER Ecdsa-Sig-Value -> r || s (64 bytes); empty if malformed
bytes der_to_raw(const bytes &der) {
	if (der.size() < 8 || der[0] != 0x30 || der[1] != der.size() - 2 || der[2] != 0x02) {
		return {};
	}
	bytes raw(64, 0);
	size_t pos = 2;
	for (int part = 0; part < 2; ++part) {
		if (pos + 2 > der.size() || der[pos] != 0x02) {
			return {};
		}
		size_t len = der[pos + 1];
		const uint8_t *v = &der[pos + 2];
		if (pos + 2 + len > der.size()) {
			return {};
		}
		while (len > 32 && *v == 0) {
			++v;
			--len;
		}
		if (len > 32) {
			return {};
		}
		std::copy(v, v + len, raw.begin() + part * 32 + (32 - len));
		pos += 2 + der[pos + 1];
	}
	return raw;
}

bool verify_es256(const uint8_t *public_key64, const bytes &message, const bytes &der_signature) {
	const bytes raw = der_to_raw(der_signature);
	const bytes hash = sha256(message);
	return raw.size() == 64 && uECC_verify(public_key64, hash.data(), 32, raw.data(), uECC_secp256r1()) == 1;
}

// the length of a DER element starting at `p`
size_t der_element_size(const uint8_t *p) {
	if (p[1] < 0x80) {
		return 2 + p[1];
	}
	if (p[1] == 0x81) {
		return 3 + p[2];
	}
	return 4 + ((p[2] << 8) | p[3]);
}

const bytes spki_prefix{
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
};

class Ctap1Test : public testing::Test {
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
	uint8_t u2f_response[1024]{};
	bytes data; // the last U2F response without the status word
	uint16_t sw{};

	const bytes challenge = bytes(32, 0xc1);
	const bytes application = sha256(std::string("https://u2f.example"));

	Ctap1Test() {
		test_reset_user_presence();
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	void apdu(const bytes &request) {
		const size_t n = ctap1_request(&ctap, request.data(), request.size(), u2f_response, sizeof(u2f_response));
		ASSERT_GE(n, 2u);
		sw = static_cast<uint16_t>((u2f_response[n - 2] << 8) | u2f_response[n - 1]);
		data.assign(u2f_response, u2f_response + n - 2);
	}

	// extended length encoding, with Le (as python-fido2 sends it)
	static bytes extended(uint8_t ins, uint8_t p1, const bytes &payload) {
		bytes r{0x00, ins, p1, 0x00, 0x00, static_cast<uint8_t>(payload.size() >> 8), static_cast<uint8_t>(payload.size())};
		r.insert(r.end(), payload.begin(), payload.end());
		r.insert(r.end(), {0x00, 0x00});
		return r;
	}

	struct Registered {
		bytes public_key; // 64 bytes (x || y)
		bytes key_handle;
		bytes cert;
		bytes signature;
	};

	Registered do_register(const bytes &app) {
		bytes payload = challenge;
		payload.insert(payload.end(), app.begin(), app.end());
		apdu(extended(CTAP1_INS_REGISTER, 0x00, payload));
		Registered r;
		EXPECT_EQ(sw, CTAP1_SW_NO_ERROR);
		if (sw != CTAP1_SW_NO_ERROR) {
			return r;
		}
		EXPECT_EQ(data[0], 0x05);
		EXPECT_EQ(data[1], 0x04);
		r.public_key.assign(data.begin() + 2, data.begin() + 66);
		const size_t kh = data[66];
		r.key_handle.assign(data.begin() + 67, data.begin() + 67 + kh);
		const size_t cert_at = 67 + kh;
		const size_t cert_size = der_element_size(&data[cert_at]);
		r.cert.assign(data.begin() + cert_at, data.begin() + cert_at + cert_size);
		r.signature.assign(data.begin() + cert_at + cert_size, data.end());
		return r;
	}

	bytes authenticate_payload(const bytes &app, const bytes &key_handle) {
		bytes payload = challenge;
		payload.insert(payload.end(), app.begin(), app.end());
		payload.push_back(static_cast<uint8_t>(key_handle.size()));
		payload.insert(payload.end(), key_handle.begin(), key_handle.end());
		return payload;
	}
};

TEST_F(Ctap1Test, Version) {
	apdu({0x00, CTAP1_INS_VERSION, 0x00, 0x00});
	EXPECT_EQ(sw, CTAP1_SW_NO_ERROR);
	EXPECT_EQ(std::string(data.begin(), data.end()), "U2F_V2");
	apdu({0x00, CTAP1_INS_VERSION, 0x00, 0x00, 0x00, 0x00, 0x00});
	EXPECT_EQ(sw, CTAP1_SW_NO_ERROR);
	apdu(extended(CTAP1_INS_VERSION, 0x00, {0x01}));
	EXPECT_EQ(sw, CTAP1_SW_WRONG_LENGTH);
}

TEST_F(Ctap1Test, BadClaInsAndLength) {
	apdu({0x80, CTAP1_INS_VERSION, 0x00, 0x00});
	EXPECT_EQ(sw, CTAP1_SW_CLA_NOT_SUPPORTED);
	apdu({0x00, 0x40, 0x00, 0x00});
	EXPECT_EQ(sw, CTAP1_SW_INS_NOT_SUPPORTED);
	apdu({0x00, 0x01});
	EXPECT_EQ(sw, CTAP1_SW_WRONG_LENGTH);
	// Lc says 64, only 3 bytes follow
	apdu({0x00, CTAP1_INS_REGISTER, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x02, 0x03});
	EXPECT_EQ(sw, CTAP1_SW_WRONG_LENGTH);
	apdu(extended(CTAP1_INS_REGISTER, 0x00, bytes(63, 0x00)));
	EXPECT_EQ(sw, CTAP1_SW_WRONG_LENGTH);
}

TEST_F(Ctap1Test, Register) {
	Registered r = do_register(application);
	ASSERT_EQ(r.key_handle.size(), 32u);
	EXPECT_EQ(test_up_calls, 1u);
	// the attestation certificate holds the attestation public key
	auto at = std::search(r.cert.begin(), r.cert.end(), spki_prefix.begin(), spki_prefix.end());
	ASSERT_NE(at, r.cert.end());
	const bytes attestation_key(at + spki_prefix.size(), at + spki_prefix.size() + 64);
	// signed: 0x00 || application || challenge || key handle || 0x04 || public key
	bytes message{0x00};
	message.insert(message.end(), application.begin(), application.end());
	message.insert(message.end(), challenge.begin(), challenge.end());
	message.insert(message.end(), r.key_handle.begin(), r.key_handle.end());
	message.push_back(0x04);
	message.insert(message.end(), r.public_key.begin(), r.public_key.end());
	EXPECT_TRUE(verify_es256(attestation_key.data(), message, r.signature));

	// the certificate is self-signed: its signature verifies with its own key
	const uint8_t *c = r.cert.data();
	const size_t outer_header = r.cert[1] == 0x82 ? 4 : 3;
	const size_t tbs_size = der_element_size(c + outer_header);
	const bytes tbs(c + outer_header, c + outer_header + tbs_size);
	const size_t sig_alg_size = der_element_size(c + outer_header + tbs_size);
	const uint8_t *bit_string = c + outer_header + tbs_size + sig_alg_size;
	ASSERT_EQ(bit_string[0], 0x03);
	const bytes cert_sig(bit_string + 3, static_cast<const uint8_t *>(r.cert.data() + r.cert.size())); // 03 len 00 sig
	EXPECT_TRUE(verify_es256(attestation_key.data(), tbs, cert_sig));

	// one attestation per authenticator: the next registration has the same certificate
	Registered r2 = do_register(application);
	EXPECT_EQ(r2.cert, r.cert);
	EXPECT_NE(r2.key_handle, r.key_handle);
}

TEST_F(Ctap1Test, RegisterWithoutUserPresence) {
	test_up_result = CTAP_UP_RESULT_TIMEOUT;
	bytes payload = challenge;
	payload.insert(payload.end(), application.begin(), application.end());
	apdu(extended(CTAP1_INS_REGISTER, 0x00, payload));
	EXPECT_EQ(sw, CTAP1_SW_CONDITIONS_NOT_SATISFIED);
}

TEST_F(Ctap1Test, AuthenticateCheckOnly) {
	Registered r = do_register(application);
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_CHECK_ONLY, authenticate_payload(application, r.key_handle)));
	EXPECT_EQ(sw, CTAP1_SW_CONDITIONS_NOT_SATISFIED);
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_CHECK_ONLY,
		authenticate_payload(sha256(std::string("https://other.example")), r.key_handle)));
	EXPECT_EQ(sw, CTAP1_SW_WRONG_DATA);
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_CHECK_ONLY, authenticate_payload(application, bytes(32, 0x55))));
	EXPECT_EQ(sw, CTAP1_SW_WRONG_DATA);
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_CHECK_ONLY, authenticate_payload(application, bytes(16, 0x55))));
	EXPECT_EQ(sw, CTAP1_SW_WRONG_DATA);
}

TEST_F(Ctap1Test, AuthenticateEnforceUserPresence) {
	Registered r = do_register(application);
	test_up_calls = 0;
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_ENFORCE_USER_PRESENCE, authenticate_payload(application, r.key_handle)));
	ASSERT_EQ(sw, CTAP1_SW_NO_ERROR);
	EXPECT_EQ(test_up_calls, 1u);
	EXPECT_EQ(data[0], 0x01);
	// signed: application || user presence || counter || challenge
	bytes message = application;
	message.insert(message.end(), data.begin(), data.begin() + 5);
	message.insert(message.end(), challenge.begin(), challenge.end());
	EXPECT_TRUE(verify_es256(r.public_key.data(), message, bytes(data.begin() + 5, data.end())));
	const uint32_t counter1 = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];

	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_ENFORCE_USER_PRESENCE, authenticate_payload(application, r.key_handle)));
	ASSERT_EQ(sw, CTAP1_SW_NO_ERROR);
	const uint32_t counter2 = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
	EXPECT_GT(counter2, counter1);

	test_up_result = CTAP_UP_RESULT_TIMEOUT;
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_ENFORCE_USER_PRESENCE, authenticate_payload(application, r.key_handle)));
	EXPECT_EQ(sw, CTAP1_SW_CONDITIONS_NOT_SATISFIED);
}

TEST_F(Ctap1Test, AuthenticateDontEnforceUserPresence) {
	Registered r = do_register(application);
	test_up_calls = 0;
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_DONT_ENFORCE_USER_PRESENCE,
		authenticate_payload(application, r.key_handle)));
	ASSERT_EQ(sw, CTAP1_SW_NO_ERROR);
	EXPECT_EQ(test_up_calls, 0u);
	EXPECT_EQ(data[0], 0x00);
	apdu(extended(CTAP1_INS_AUTHENTICATE, 0x42, authenticate_payload(application, r.key_handle)));
	EXPECT_EQ(sw, CTAP1_SW_WRONG_DATA);
}

TEST_F(Ctap1Test, U2fCredentialWithGetAssertion) {
	// the appid extension: rpId = the AppID, its hash is the application parameter
	Registered r = do_register(application);
	const std::string app_id = "https://u2f.example";
	bytes ga{0xa3, 0x01, static_cast<uint8_t>(0x60 | app_id.size())};
	ga.insert(ga.end(), app_id.begin(), app_id.end());
	ga.insert(ga.end(), {0x02, 0x58, 0x20});
	ga.insert(ga.end(), 32, 0x44);
	ga.insert(ga.end(), {0x03, 0x81, 0xa2, 0x62, 'i', 'd', 0x58, 0x20});
	ga.insert(ga.end(), r.key_handle.begin(), r.key_handle.end());
	ga.insert(ga.end(), {0x64, 't', 'y', 'p', 'e', 0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
	status = ctap_request(&ctap, CTAP_CMD_GET_ASSERTION, ga.size(), ga.data(), &response);
	EXPECT_EQ(status, CTAP2_OK);
}

TEST_F(Ctap1Test, Ctap2CredentialWithU2f) {
	// makeCredential for rp "a.b" (ES256), then U2F_AUTHENTICATE with SHA-256("a.b")
	bytes mc{0xa4, 0x01, 0x58, 0x20};
	mc.insert(mc.end(), 32, 0x11);
	mc.insert(mc.end(), {0x02, 0xa1, 0x62, 'i', 'd', 0x63, 'a', '.', 'b'});
	mc.insert(mc.end(), {0x03, 0xa1, 0x62, 'i', 'd', 0x41, 0x01});
	mc.insert(mc.end(), {0x04, 0x81, 0xa2, 0x63, 'a', 'l', 'g', 0x26, 0x64, 't', 'y', 'p', 'e',
		0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
	status = ctap_request(&ctap, CTAP_CMD_MAKE_CREDENTIAL, mc.size(), mc.data(), &response);
	ASSERT_EQ(status, CTAP2_OK);
	// the credential ID: in authData (2nd member) after rpIdHash, flags, signCount, aaguid, length
	ctap_storage_item_t item{.key = CTAP_STORAGE_KEY_CREDENTIAL};
	ASSERT_EQ(storage.find_item(&storage, &item), CTAP_STORAGE_OK);
	const bytes key_handle(item.data + 4, item.data + 4 + 32); // ctap_credential_source_t: flags, id
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_DONT_ENFORCE_USER_PRESENCE,
		authenticate_payload(sha256(std::string("a.b")), key_handle)));
	EXPECT_EQ(sw, CTAP1_SW_NO_ERROR);
}

TEST_F(Ctap1Test, ResetMakesANewAttestation) {
	Registered r = do_register(application);
	status = ctap_request(&ctap, CTAP_CMD_RESET, 0, nullptr, &response);
	ASSERT_EQ(status, CTAP2_OK);
	Registered r2 = do_register(application);
	EXPECT_NE(r2.cert, r.cert);
	// the old key handle is gone
	apdu(extended(CTAP1_INS_AUTHENTICATE, CTAP1_AUTH_CHECK_ONLY, authenticate_payload(application, r.key_handle)));
	EXPECT_EQ(sw, CTAP1_SW_WRONG_DATA);
}

} // namespace
