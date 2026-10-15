#ifndef LIONKEY_CTAP_TEST_H
#define LIONKEY_CTAP_TEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool test_validate_cbor(const uint8_t *data, size_t data_size);

// test doubles of the platform functions (time.c, wait_for_user_presence.c)
#include <ctap.h>
extern uint32_t test_current_time;
extern ctap_user_presence_result_t test_up_result;
extern unsigned test_up_calls;
extern ctap_user_presence_result_t test_long_touch_result;
extern unsigned test_long_touch_calls;
extern uint32_t test_long_touch_ms;
// back to: time 0, both waits answer ALLOW, no calls recorded
void test_reset_user_presence(void);

#endif // LIONKEY_CTAP_TEST_H
