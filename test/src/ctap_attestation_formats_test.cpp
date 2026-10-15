#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <initializer_list>
#include <string>
#include <vector>
extern "C" {
#include <ctap.h>
#include <ctap_crypto_software.h>
#include <ctap_memory_storage.h>
#include <ctap_test.h>
}
namespace {

// makeCredential attestationFormatsPreference (0x0B) and getInfo attestationFormats (0x16), CTAP 2.2

using bytes = std::vector<uint8_t>;

class CtapAttestationFormatsTest : public testing::Test {
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
	CborParser parser{};

	CtapAttestationFormatsTest() {
		test_reset_user_presence();
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	void request(uint8_t cmd, const bytes &params) {
		status = ctap_request(&ctap, cmd, params.size(), params.data(), &response);
	}

	// makeCredential for "a.b" (ES256); `preference`: the raw CBOR of 0x0B, empty: absent
	void make_credential(const bytes &preference) {
		bytes r{static_cast<uint8_t>(preference.empty() ? 0xa4 : 0xa5), 0x01, 0x58, 0x20};
		r.insert(r.end(), 32, 0x11);
		r.insert(r.end(), {0x02, 0xa1, 0x62, 'i', 'd', 0x63, 'a', '.', 'b'});
		r.insert(r.end(), {0x03, 0xa1, 0x62, 'i', 'd', 0x41, 0x01});
		r.insert(r.end(), {0x04, 0x81, 0xa2, 0x63, 'a', 'l', 'g', 0x26, 0x64, 't', 'y', 'p', 'e',
			0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'});
		if (!preference.empty()) {
			r.push_back(0x0b);
			r.insert(r.end(), preference.begin(), preference.end());
		}
		request(CTAP_CMD_MAKE_CREDENTIAL, r);
	}

	static bytes strings(std::initializer_list<std::string> list) {
		bytes a{static_cast<uint8_t>(0x80 | list.size())};
		for (const auto &s : list) {
			a.push_back(static_cast<uint8_t>(0x60 | s.size()));
			a.insert(a.end(), s.begin(), s.end());
		}
		return a;
	}

	// the response's member `key`
	CborValue member(uint64_t key) {
		CborValue it;
		CborValue map;
		EXPECT_EQ(cbor_parser_init(response.data, response.length, 0, &parser, &it), CborNoError);
		EXPECT_EQ(cbor_value_enter_container(&it, &map), CborNoError);
		while (!cbor_value_at_end(&map)) {
			uint64_t k;
			EXPECT_EQ(cbor_value_get_uint64(&map, &k), CborNoError);
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
			if (k == key) {
				return map;
			}
			EXPECT_EQ(cbor_value_advance(&map), CborNoError);
		}
		ADD_FAILURE() << "no member " << key;
		return map;
	}

	std::string fmt() {
		CborValue v = member(CTAP_makeCredential_res_fmt);
		char text[16] = {};
		size_t n = sizeof(text) - 1;
		EXPECT_EQ(cbor_value_copy_text_string(&v, text, &n, nullptr), CborNoError);
		return std::string(text, n);
	}

	bytes auth_data() {
		CborValue v = member(CTAP_makeCredential_res_authData);
		EXPECT_TRUE(cbor_value_is_byte_string(&v));
		size_t n = 0;
		EXPECT_EQ(cbor_value_calculate_string_length(&v, &n), CborNoError);
		bytes out(n);
		EXPECT_EQ(cbor_value_copy_byte_string(&v, out.data(), &n, nullptr), CborNoError);
		return out;
	}

	size_t att_stmt_entries() {
		CborValue v = member(CTAP_makeCredential_res_attStmt);
		size_t n = 99;
		EXPECT_TRUE(cbor_value_is_map(&v));
		EXPECT_EQ(cbor_value_get_map_length(&v, &n), CborNoError);
		return n;
	}
};

TEST_F(CtapAttestationFormatsTest, DefaultIsPacked) {
	make_credential({});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(fmt(), "packed");
	EXPECT_EQ(att_stmt_entries(), 2u); // alg, sig
}

TEST_F(CtapAttestationFormatsTest, None) {
	make_credential(strings({"none"}));
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	EXPECT_EQ(fmt(), "none");
	EXPECT_EQ(att_stmt_entries(), 0u);
}

TEST_F(CtapAttestationFormatsTest, TheFirstSupportedWins) {
	make_credential(strings({"tpm", "none", "packed"}));
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(fmt(), "none");
	make_credential(strings({"apple", "packed", "none"}));
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(fmt(), "packed");
}

TEST_F(CtapAttestationFormatsTest, NothingSupportedOrEmptyIsPacked) {
	make_credential(strings({"tpm", "android-key"}));
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(fmt(), "packed");
	make_credential({0x80});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(fmt(), "packed");
}

TEST_F(CtapAttestationFormatsTest, NotAStringIsRefused) {
	make_credential({0x81, 0x01});
	EXPECT_EQ(status, CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

TEST_F(CtapAttestationFormatsTest, NotAStringAfterASupportedOneIsRefused) {
	bytes preference = strings({"packed"});
	preference[0] = 0x82;
	preference.push_back(0x05); // ["packed", 5]
	make_credential(preference);
	EXPECT_EQ(status, CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
}

TEST_F(CtapAttestationFormatsTest, NoneKeepsTheAuthData) {
	make_credential(strings({"packed"}));
	ASSERT_EQ(status, CTAP2_OK);
	const bytes packed = auth_data();
	make_credential(strings({"none"}));
	ASSERT_EQ(status, CTAP2_OK);
	const bytes none = auth_data();
	// rpIdHash (32), flags (1), signCount (4), AAGUID (16), credentialIdLength (2), credentialId, publicKey
	ASSERT_GT(packed.size(), 55u);
	ASSERT_EQ(none.size(), packed.size());
	EXPECT_EQ(bytes(none.begin(), none.begin() + 33), bytes(packed.begin(), packed.begin() + 33));
	EXPECT_NE(none[32] & CTAP_authenticator_data_flags_at, 0);
	EXPECT_EQ(bytes(none.begin() + 37, none.begin() + 55), bytes(packed.begin() + 37, packed.begin() + 55));
	const size_t id_length = (static_cast<size_t>(none[53]) << 8) | none[54];
	ASSERT_LT(55 + id_length, none.size());
	EXPECT_NE(bytes(none.begin() + 55, none.begin() + 55 + static_cast<long>(id_length)),
		bytes(packed.begin() + 55, packed.begin() + 55 + static_cast<long>(id_length))); // a new credential
	// the public key: a COSE_Key map
	EXPECT_EQ(none[55 + id_length], packed[55 + id_length]);
	EXPECT_EQ(none[55 + id_length] & 0xe0, 0xa0);
}

TEST_F(CtapAttestationFormatsTest, GetInfoListsPackedOnly) {
	request(CTAP_CMD_GET_INFO, {});
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
	CborValue v = member(CTAP_authenticatorGetInfo_res_attestationFormats);
	ASSERT_TRUE(cbor_value_is_array(&v));
	size_t n = 0;
	EXPECT_EQ(cbor_value_get_array_length(&v, &n), CborNoError);
	EXPECT_EQ(n, 1u); // "none" is implied and not listed
	CborValue element;
	ASSERT_EQ(cbor_value_enter_container(&v, &element), CborNoError);
	bool packed = false;
	EXPECT_EQ(cbor_value_text_string_equals(&element, "packed", &packed), CborNoError);
	EXPECT_TRUE(packed);
}

} // namespace
