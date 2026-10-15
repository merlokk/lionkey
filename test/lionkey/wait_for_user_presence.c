#include <ctap.h>
#include <ctap_test.h>

ctap_user_presence_result_t test_up_result = CTAP_UP_RESULT_ALLOW;
unsigned test_up_calls = 0;

ctap_user_presence_result_t test_long_touch_result = CTAP_UP_RESULT_ALLOW;
unsigned test_long_touch_calls = 0;
uint32_t test_long_touch_ms = 0;

ctap_user_presence_result_t ctap_wait_for_user_presence(void) {
	debug_log("returning %d from ctap_wait_for_user_presence" nl, (int) test_up_result);
	test_up_calls++;
	return test_up_result;
}

ctap_user_presence_result_t ctap_wait_for_long_touch(uint32_t duration_ms) {
	debug_log("returning %d from ctap_wait_for_long_touch(%" PRIu32 ")" nl, (int) test_long_touch_result, duration_ms);
	test_long_touch_calls++;
	test_long_touch_ms = duration_ms;
	return test_long_touch_result;
}

void test_reset_user_presence(void) {
	test_up_result = CTAP_UP_RESULT_ALLOW;
	test_up_calls = 0;
	test_long_touch_result = CTAP_UP_RESULT_ALLOW;
	test_long_touch_calls = 0;
	test_long_touch_ms = 0;
	test_current_time = 0;
}
