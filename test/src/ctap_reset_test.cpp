#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <optional>
extern "C" {
#include <ctap.h>
#include <ctap_crypto_software.h>
#include <ctap_memory_storage.h>
#include <ctap_test.h>
}
namespace {

class CtapResetTest : public testing::Test {
protected:
	uint8_t ctap_response_buffer[CTAP_RESPONSE_BUFFER_SIZE]{};
	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ctap_memory_storage_context_t storage_ctx{};
	const ctap_storage_t storage = CTAP_MEMORY_STORAGE_CONST_INIT(&storage_ctx);
	ctap_state_t ctap = CTAP_STATE_CONST_INIT(&crypto, &storage);
	ctap_response_t response{
		.data_max_size = sizeof(ctap_response_buffer),
		.data = ctap_response_buffer,
	};
	uint8_t status{};

	CtapResetTest() {
		test_reset_user_presence();
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	void request(uint8_t cmd) {
		status = ctap_request(&ctap, cmd, 0, nullptr, &response);
	}

	// getInfo member `key` (unsigned integer key): its CBOR type, or nothing when absent
	std::optional<CborValue> get_info_member(uint64_t key) {
		request(CTAP_CMD_GET_INFO);
		EXPECT_EQ(status, CTAP2_OK);
		CborParser parser;
		CborValue it;
		EXPECT_EQ(cbor_parser_init(response.data, response.length, 0, &parser, &it), CborNoError);
		EXPECT_TRUE(cbor_value_is_map(&it));
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

};

TEST_F(CtapResetTest, GetInfoWithoutLongTouchHasNoLongTouchForReset) {
	EXPECT_FALSE(get_info_member(CTAP_authenticatorGetInfo_res_longTouchForReset).has_value());
}

TEST_F(CtapResetTest, GetInfoReportsLongTouchForReset) {
	ctap.long_touch_for_reset_ms = CTAP_LONG_TOUCH_FOR_RESET_MS;
	auto value = get_info_member(CTAP_authenticatorGetInfo_res_longTouchForReset);
	ASSERT_TRUE(value.has_value());
	bool long_touch = false;
	ASSERT_EQ(cbor_value_get_boolean(&*value, &long_touch), CborNoError);
	EXPECT_TRUE(long_touch);
	EXPECT_TRUE(test_validate_cbor(response.data, response.length));
}

TEST_F(CtapResetTest, ResetTakesAnOrdinaryTouchByDefault) {
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(test_up_calls, 1u);
	EXPECT_EQ(test_long_touch_calls, 0u);
}

TEST_F(CtapResetTest, ResetTakesALongTouchWhenEnabled) {
	ctap.long_touch_for_reset_ms = CTAP_LONG_TOUCH_FOR_RESET_MS;
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(test_up_calls, 0u);
	EXPECT_EQ(test_long_touch_calls, 1u);
	EXPECT_EQ(test_long_touch_ms, 5000u);
}

TEST_F(CtapResetTest, LongTouchSurvivesTheReset) {
	ctap.long_touch_for_reset_ms = CTAP_LONG_TOUCH_FOR_RESET_MS;
	request(CTAP_CMD_RESET);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(ctap.long_touch_for_reset_ms, 5000u);
}

TEST_F(CtapResetTest, LongTouchTimeout) {
	ctap.long_touch_for_reset_ms = CTAP_LONG_TOUCH_FOR_RESET_MS;
	test_long_touch_result = CTAP_UP_RESULT_TIMEOUT;
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_ERR_USER_ACTION_TIMEOUT);
}

TEST_F(CtapResetTest, LongTouchCancel) {
	ctap.long_touch_for_reset_ms = CTAP_LONG_TOUCH_FOR_RESET_MS;
	test_long_touch_result = CTAP_UP_RESULT_CANCEL;
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_ERR_KEEPALIVE_CANCEL);
}

TEST_F(CtapResetTest, LongTouchDenied) {
	// e.g. the touch was released before the duration
	ctap.long_touch_for_reset_ms = CTAP_LONG_TOUCH_FOR_RESET_MS;
	test_long_touch_result = CTAP_UP_RESULT_DENY;
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_ERR_OPERATION_DENIED);
}

TEST_F(CtapResetTest, ResetAfterTenSecondsIsNotAllowedAndWaitsForNothing) {
	ctap.long_touch_for_reset_ms = CTAP_LONG_TOUCH_FOR_RESET_MS;
	test_current_time = 10001;
	request(CTAP_CMD_RESET);
	EXPECT_EQ(status, CTAP2_ERR_NOT_ALLOWED);
	EXPECT_EQ(test_up_calls, 0u);
	EXPECT_EQ(test_long_touch_calls, 0u);
}

} // namespace
