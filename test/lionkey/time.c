#include <ctap.h>
#include <ctap_test.h>

uint32_t test_current_time = 0;

uint32_t ctap_get_current_time(void) {
	return test_current_time;
}
