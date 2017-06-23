/*
 * Copyright (C) 2016 Shane Francis / Jens Andersen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __TZAPI_H_
#define __TZAPI_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IMP_NAME "Tone 7.x FPC"

#define FP_TZAPP_PATH "/vendor/firmware/"
#define FP_TZAPP_NAME "tzfingerprint"

#define KM_TZAPP_PATH "/firmware/image/"
#define KM_TZAPP_NAME "keymaste"
#define KM_TZAPP_ALT_NAME "keymaster"

#define BUFFER_SIZE 64

#define TZ_RESPONSE_OFFSET 256

enum fingerprint_group_t {
  FPC_GROUP_NORMAL = 0x1,
  FPC_GROUP_DB = 0x2,
  FPC_GROUP_FPCDATA = 0x3,
  FPC_GROUP_DEBUG = 0x6, // I think?
  FPC_GROUP_QC = 0x07,
};

//enumerate tz app command ID's
enum fingerprint_normal_cmd_t {
    FPC_BEGIN_ENROL = 0x00,
    FPC_ENROL_STEP = 0x01,
    FPC_END_ENROL = 0x02,
    FPC_IDENTIFY = 0x03,
    FPC_UPDATE_TEMPLATE = 0x04,
    FPC_WAIT_FINGER_LOST = 0x05,
    FPC_WAIT_FINGER_DOWN = 0x07,
    FPC_GET_FINGER_STATUS =0x8,
    FPC_LOAD_EMPTY_DB = 0x0A,
    FPC_GET_FINGERPRINTS = 0xD,
    FPC_DELETE_FINGERPRINT = 0xE,
    FPC_CAPTURE_IMAGE = 0xF,
    FPC_SET_GID = 0x10,
    FPC_GET_TEMPLATE_ID = 0x11,
    FPC_INIT = 0x12,
};

enum fingerprint_fpcdata_cmd_t {
    FPC_SET_AUTH_CHALLENGE = 0x01,
    FPC_GET_AUTH_CHALLENGE = 0x02,
    FPC_AUTHORIZE_ENROL = 0x03,
    FPC_GET_AUTH_RESULT = 0x04,
    FPC_SET_KEY_DATA = 0x05,
    FPC_IS_USER_VALID = 0x07,
};

enum fingerprint_db_cmd_t {
    FPC_LOAD_DB = 0x0B,
    FPC_STORE_DB = 0x0C,
};

enum fingerprint_debug_cmd_t {
    FPC_GET_SENSOR_INFO = 0x03,
};

enum fingerprint_qc_cmd_t {
    FPC_SET_QC_AUTH_NONCE = 0x01,
    FPC_GET_QC_AUTH_RESULT = 0x02,
};

#ifdef __cplusplus
}
#endif
#endif
