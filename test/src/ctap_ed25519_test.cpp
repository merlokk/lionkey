#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <vector>
extern "C" {
#include <ctap.h>
#include <ctap_crypto_software.h>
#include <ctap_memory_storage.h>
#include <ctap_test.h>
#include <monocypher-ed25519.h>
}
namespace {

// RFC 8032 7.1. Test Vectors for Ed25519

TEST(CtapEd25519, Rfc8032Test1) {
	ctap_software_crypto_context_t ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&ctx);
	auto secret = hex::bytes<"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60">();
	auto expected_public = hex::bytes<"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a">();
	auto expected_signature = hex::bytes<
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
	>();
	uint8_t public_key[32];
	ASSERT_EQ(crypto.ed25519_compute_public_key(&crypto, secret.data(), public_key), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES(public_key, expected_public.data());
	uint8_t signature[64];
	ASSERT_EQ(crypto.ed25519_sign(&crypto, secret.data(), nullptr, 0, signature), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES(signature, expected_signature.data());
}

TEST(CtapEd25519, Rfc8032Test2) {
	ctap_software_crypto_context_t ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&ctx);
	auto secret = hex::bytes<"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb">();
	auto expected_public = hex::bytes<"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c">();
	auto message = hex::bytes<"72">();
	auto expected_signature = hex::bytes<
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
		"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
	>();
	uint8_t public_key[32];
	ASSERT_EQ(crypto.ed25519_compute_public_key(&crypto, secret.data(), public_key), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES(public_key, expected_public.data());
	uint8_t signature[64];
	ASSERT_EQ(crypto.ed25519_sign(&crypto, secret.data(), message.data(), message.size(), signature), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES(signature, expected_signature.data());
}

TEST(CtapEd25519, Rfc8032Test3) {
	ctap_software_crypto_context_t ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&ctx);
	auto secret = hex::bytes<"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7">();
	auto expected_public = hex::bytes<"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025">();
	auto message = hex::bytes<"af82">();
	auto expected_signature = hex::bytes<
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
		"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
	>();
	uint8_t public_key[32];
	ASSERT_EQ(crypto.ed25519_compute_public_key(&crypto, secret.data(), public_key), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES(public_key, expected_public.data());
	uint8_t signature[64];
	ASSERT_EQ(crypto.ed25519_sign(&crypto, secret.data(), message.data(), message.size(), signature), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES(signature, expected_signature.data());
}

TEST(CtapEd25519, KeepsThePrivateKey) {
	// Monocypher's key pair function wipes its seed: ours must work on a copy
	ctap_software_crypto_context_t ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&ctx);
	auto secret = hex::bytes<"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60">();
	const auto copy = secret;
	uint8_t out[64];
	crypto.ed25519_compute_public_key(&crypto, secret.data(), out);
	crypto.ed25519_sign(&crypto, secret.data(), nullptr, 0, out);
	EXPECT_EQ(secret, copy);
}

// makeCredential / getAssertion with Ed25519 credentials

class CtapEd25519CredentialTest : public testing::Test {
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

	CtapEd25519CredentialTest() {
		test_reset_user_presence();
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	void request(uint8_t cmd, const std::vector<uint8_t> &params) {
		status = ctap_request(&ctap, cmd, params.size(), params.data(), &response);
	}

	// the response map's member `key` (a byte or text string, or an int as its CBOR bytes)
	std::vector<uint8_t> member(uint64_t key) {
		CborParser parser;
		CborValue it;
		CborValue map;
		EXPECT_EQ(cbor_parser_init(response.data, response.length, 0, &parser, &it), CborNoError);
		EXPECT_EQ(cbor_value_enter_container(&it, &map), CborNoError);
		while (!cbor_value_at_end(&map)) {
			uint64_t k;
			EXPECT_EQ(cbor_value_get_uint64(&map, &k), CborNoError);
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
			if (k == key) {
				const uint8_t *start = cbor_value_get_next_byte(&map);
				if (cbor_value_is_byte_string(&map)) {
					size_t n = 0;
					EXPECT_EQ(cbor_value_calculate_string_length(&map, &n), CborNoError);
					std::vector<uint8_t> out(n);
					EXPECT_EQ(cbor_value_copy_byte_string(&map, out.data(), &n, nullptr), CborNoError);
					return out;
				}
				CborValue next = map;
				EXPECT_EQ(cbor_value_advance(&next), CborNoError);
				return {start, cbor_value_get_next_byte(&next)};
			}
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
		}
		ADD_FAILURE() << "no member " << key;
		return {};
	}

	// makeCredential for rp "a.b" with these COSE algorithms (each -1..-24): the response status
	void make_credential(std::initializer_list<int> algs) {
		std::vector<uint8_t> r = {0xa4, 0x01, 0x58, 0x20};
		r.insert(r.end(), 32, 0x11);
		r.insert(r.end(), {0x02, 0xa1, 0x62, 'i', 'd', 0x63, 'a', '.', 'b'});
		r.insert(r.end(), {0x03, 0xa1, 0x62, 'i', 'd', 0x41, 0x01});
		r.push_back(0x04);
		r.push_back(static_cast<uint8_t>(0x80 | algs.size()));
		for (int alg : algs) {
			r.insert(r.end(), {0xa2, 0x63, 'a', 'l', 'g'});
			r.push_back(alg >= -24 ? static_cast<uint8_t>(0x20 + (-1 - alg)) : 0x38);
			if (alg < -24) {
				r.push_back(static_cast<uint8_t>(-1 - alg));
			}
			r.insert(r.end(), {0x64, 't', 'y', 'p', 'e', 0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
		}
		request(CTAP_CMD_MAKE_CREDENTIAL, r);
	}

	struct Made {
		std::vector<uint8_t> auth_data;
		std::vector<uint8_t> credential_id;
		std::vector<uint8_t> cose_key;
	};

	Made made() {
		Made m;
		m.auth_data = member(2);
		// rpIdHash (32), flags, signCount (4), aaguid (16), credentialIdLength (2)
		const size_t id_length = (m.auth_data[53] << 8) | m.auth_data[54];
		m.credential_id.assign(m.auth_data.begin() + 55, m.auth_data.begin() + 55 + id_length);
		m.cose_key.assign(m.auth_data.begin() + 55 + id_length, m.auth_data.end());
		return m;
	}

	void get_assertion(const std::vector<uint8_t> &credential_id, uint8_t cdh_byte) {
		std::vector<uint8_t> r = {0xa3, 0x01, 0x63, 'a', '.', 'b', 0x02, 0x58, 0x20};
		r.insert(r.end(), 32, cdh_byte);
		r.insert(r.end(), {0x03, 0x81, 0xa2, 0x62, 'i', 'd', 0x58, static_cast<uint8_t>(credential_id.size())});
		r.insert(r.end(), credential_id.begin(), credential_id.end());
		r.insert(r.end(), {0x64, 't', 'y', 'p', 'e', 0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
		request(CTAP_CMD_GET_ASSERTION, r);
	}

	static bool verify(
		const std::vector<uint8_t> &public_key,
		const std::vector<uint8_t> &signature,
		const std::vector<uint8_t> &auth_data,
		uint8_t cdh_byte
	) {
		std::vector<uint8_t> message = auth_data;
		message.insert(message.end(), 32, cdh_byte);
		return signature.size() == 64
			&& crypto_ed25519_check(signature.data(), public_key.data(), message.data(), message.size()) == 0;
	}
};

// COSE_Key OKP prefix for alg -8 / -19: {1: 1, 3: alg, -1: 6, -2: h'<32>'}
const std::vector<uint8_t> okp_eddsa_prefix{0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20};
const std::vector<uint8_t> okp_ed25519_prefix{0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58, 0x20};

TEST_F(CtapEd25519CredentialTest, GetInfoListsTheAlgorithms) {
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	auto algorithms = member(CTAP_authenticatorGetInfo_res_algorithms);
	// [{"alg": -7, ...}, {"alg": -8, ...}, {"alg": -19, ...}]
	ASSERT_GE(algorithms.size(), 1u);
	EXPECT_EQ(algorithms[0], 0x83);
}

TEST_F(CtapEd25519CredentialTest, EdDsaCredential) {
	make_credential({-8, -7});
	ASSERT_EQ(status, CTAP2_OK);
	Made m = made();
	ASSERT_EQ(m.cose_key.size(), okp_eddsa_prefix.size() + 32);
	EXPECT_TRUE(std::equal(okp_eddsa_prefix.begin(), okp_eddsa_prefix.end(), m.cose_key.begin()));
	std::vector<uint8_t> public_key(m.cose_key.end() - 32, m.cose_key.end());

	// packed self attestation: {"alg": -8, "sig": h'<64>'} over authData || clientDataHash
	auto att_stmt = member(3);
	ASSERT_EQ(att_stmt.size(), 1 + 4 + 1 + 4 + 2 + 64u);
	EXPECT_EQ(att_stmt[5], 0x27);
	std::vector<uint8_t> att_sig(att_stmt.end() - 64, att_stmt.end());
	EXPECT_TRUE(verify(public_key, att_sig, m.auth_data, 0x11));

	get_assertion(m.credential_id, 0x22);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(verify(public_key, member(3), member(2), 0x22));
	// a different client data hash does not verify
	EXPECT_FALSE(verify(public_key, member(3), member(2), 0x23));
}

TEST_F(CtapEd25519CredentialTest, Ed25519Credential) {
	make_credential({-19});
	ASSERT_EQ(status, CTAP2_OK);
	Made m = made();
	ASSERT_EQ(m.cose_key.size(), okp_ed25519_prefix.size() + 32);
	EXPECT_TRUE(std::equal(okp_ed25519_prefix.begin(), okp_ed25519_prefix.end(), m.cose_key.begin()));
	std::vector<uint8_t> public_key(m.cose_key.end() - 32, m.cose_key.end());
	get_assertion(m.credential_id, 0x33);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(verify(public_key, member(3), member(2), 0x33));
}

TEST_F(CtapEd25519CredentialTest, TheHostsOrderDecides) {
	make_credential({-7, -8});
	ASSERT_EQ(status, CTAP2_OK);
	Made m = made();
	// EC2: {1: 2, 3: -7, ...}
	ASSERT_GE(m.cose_key.size(), 5u);
	EXPECT_EQ(m.cose_key[2], 0x02);
	EXPECT_EQ(m.cose_key[4], 0x26);
}

TEST_F(CtapEd25519CredentialTest, UnsupportedAlgorithm) {
	make_credential({-257});
	EXPECT_EQ(status, CTAP2_ERR_UNSUPPORTED_ALGORITHM);
}

} // namespace
