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

#ifndef __TZAPI_TONE_H_
#define __TZAPI_TONE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum fingerprint_tone_group_t {
  TONE_FPC_GROUP_NORMAL = 0x1,
  TONE_FPC_GROUP_DB = 0x2,
  TONE_FPC_GROUP_FPCDATA = 0x3,
  TONE_FPC_GROUP_DEBUG = 0x6, // I think?
  TONE_FPC_GROUP_QC = 0x07,
};

//enumerate tz app command ID's
enum fingerprint_tone_normal_cmd_t {
    TONE_FPC_BEGIN_ENROL = 0x00,
    TONE_FPC_ENROL_STEP = 0x01,
    TONE_FPC_END_ENROL = 0x02,
    TONE_FPC_IDENTIFY = 0x03,
    TONE_FPC_UPDATE_TEMPLATE = 0x04,
    TONE_FPC_WAIT_FINGER_LOST = 0x05,
    TONE_FPC_WAIT_FINGER_DOWN = 0x07,
    TONE_FPC_GET_FINGER_STATUS =0x8,
    TONE_FPC_LOAD_EMPTY_DB = 0x0A,
    TONE_FPC_GET_FINGERPRINTS = 0xD,
    TONE_FPC_DELETE_FINGERPRINT = 0xE,
    TONE_FPC_CAPTURE_IMAGE = 0xF,
    TONE_FPC_SET_GID = 0x10,
    TONE_FPC_GET_TEMPLATE_ID = 0x11,
    TONE_FPC_INIT = 0x12,
};

enum fingerprint_tone_fpcdata_cmd_t {
    TONE_FPC_SET_AUTH_CHALLENGE = 0x01,
    TONE_FPC_GET_AUTH_CHALLENGE = 0x02,
    TONE_FPC_AUTHORIZE_ENROL = 0x03,
    TONE_FPC_GET_AUTH_RESULT = 0x04,
    TONE_FPC_SET_KEY_DATA = 0x05,
    TONE_FPC_IS_USER_VALID = 0x07,
};

enum fingerprint_tone_db_cmd_t {
    TONE_FPC_LOAD_DB = 0x0B,
    TONE_FPC_STORE_DB = 0x0C,
};

enum fingerprint_tone_debug_cmd_t {
    TONE_FPC_GET_SENSOR_INFO = 0x03,
};

enum fingerprint_tone_qc_cmd_t {
    TONE_FPC_SET_QC_AUTH_NONCE = 0x01,
    TONE_FPC_GET_QC_AUTH_RESULT = 0x02,
};

static struct tz_command_list_t tone_commands = {
 .fpc_begin_enrol = {TONE_FPC_GROUP_NORMAL, TONE_FPC_BEGIN_ENROL},
 .fpc_enrol_step = {TONE_FPC_GROUP_NORMAL, TONE_FPC_ENROL_STEP},
 .fpc_end_enrol = {TONE_FPC_GROUP_NORMAL, TONE_FPC_END_ENROL},
 .fpc_identify = {TONE_FPC_GROUP_NORMAL, TONE_FPC_IDENTIFY},
 .fpc_wait_for_finger_lost = {TONE_FPC_GROUP_NORMAL, TONE_FPC_WAIT_FINGER_LOST},
 .fpc_wait_for_finger_down = {TONE_FPC_GROUP_NORMAL, TONE_FPC_WAIT_FINGER_DOWN},
 .fpc_get_finger_status = {TONE_FPC_GROUP_NORMAL, TONE_FPC_GET_FINGER_STATUS},
 .fpc_load_empty_db = {TONE_FPC_GROUP_NORMAL, TONE_FPC_LOAD_EMPTY_DB},
 .fpc_get_fingerprints = {TONE_FPC_GROUP_NORMAL, TONE_FPC_GET_FINGERPRINTS},
 .fpc_delete_fingerprints = {TONE_FPC_GROUP_NORMAL, TONE_FPC_DELETE_FINGERPRINT},
 .fpc_capture_image = {TONE_FPC_GROUP_NORMAL, TONE_FPC_CAPTURE_IMAGE},
 .fpc_set_gid = {TONE_FPC_GROUP_NORMAL, TONE_FPC_SET_GID},
 .fpc_get_template_id = {TONE_FPC_GROUP_NORMAL, TONE_FPC_GET_TEMPLATE_ID},
 .fpc_init = {TONE_FPC_GROUP_NORMAL, TONE_FPC_INIT},
 .fpc_set_auth_challenge = {TONE_FPC_GROUP_FPCDATA, TONE_FPC_SET_AUTH_CHALLENGE},
 .fpc_get_auth_challenge = {TONE_FPC_GROUP_FPCDATA, TONE_FPC_GET_AUTH_CHALLENGE},
 .fpc_auth_enrol = {TONE_FPC_GROUP_FPCDATA, TONE_FPC_AUTHORIZE_ENROL},
 .fpc_get_auth_result = {TONE_FPC_GROUP_FPCDATA, TONE_FPC_GET_AUTH_RESULT},
 .fpc_set_key_data = {TONE_FPC_GROUP_FPCDATA, TONE_FPC_SET_KEY_DATA},
 .fpc_load_db = {TONE_FPC_GROUP_DB, TONE_FPC_LOAD_DB},
 .fpc_store_db = {TONE_FPC_GROUP_DB, TONE_FPC_STORE_DB},
 .tz_response_offset = 256,
 .tz_imp_name = "Tone 7.x FPC (Hybrid)",
};

#ifdef __cplusplus
}
#endif
#endif
