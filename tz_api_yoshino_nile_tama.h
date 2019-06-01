#ifndef __TZAPI_YOSHINO_NILE_TAMA_H_
#define __TZAPI_YOSHINO_NILE_TAMA_H_

#include "tz_api_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint32_t ret_val;
    uint32_t gesture;
    uint32_t mask;  // ?
    uint32_t finger_on;
    uint32_t should_poll;
} fpc_navi_cmd_t;

#ifdef __cplusplus
}
#endif
#endif
