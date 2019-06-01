#ifndef __TZAPI_COMMON_H_
#define __TZAPI_COMMON_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum fingerprint_navigation_t {
    FPC_NAVIGATION_ENTER = 0x1,
    FPC_NAVIGATION_EXIT = 0x2,
    FPC_NAVIGATION_POLL = 0x3,
};

enum fingerprint_gesture_t {
    // Returned when the finger leaves the sensor without detecting
    // a gesture. Can be interpreted as "tap"
    FPC_GESTURE_GONE = 1,
    FPC_GESTURE_HOLD = 2,
    FPC_GESTURE_UP = 3,
    FPC_GESTURE_DOWN = 4,
    FPC_GESTURE_LEFT = 5,
    FPC_GESTURE_RIGHT = 6,
    FPC_GESTURE_DOUBLE_TAP = 7,
};

#ifdef __cplusplus
}
#endif
#endif
