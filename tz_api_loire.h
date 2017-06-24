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

#ifndef __TZAPI_LOIR_H_
#define __TZAPI_LOIR_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum fingerprint_loire_group_t {
  LOIRE_FPC_GROUP_NORMAL = 0x1,
  LOIRE_FPC_GROUP_DB = 0x2,
  LOIRE_FPC_GROUP_FPCDATA = 0x3,
  LOIRE_FPC_GROUP_DEBUG = 0x6, // I think?
};

//enumerate tz app command ID's
enum fingerprint_loire_normal_cmd_t {
  LOIRE_FPC_BEGIN_ENROL = 0x00,
  LOIRE_FPC_ENROL_STEP = 0x01,
  LOIRE_FPC_END_ENROL = 0x02,
  LOIRE_FPC_IDENTIFY = 0x03,
  LOIRE_FPC_WAIT_FINGER_LOST = 0x04,
  LOIRE_FPC_WAIT_FINGER_DOWN = 0x06,
  LOIRE_FPC_GET_FINGER_STATUS =0x07,
  LOIRE_FPC_LOAD_EMPTY_DB = 0x09,
  LOIRE_FPC_GET_FINGERPRINTS = 0x0C,
  LOIRE_FPC_DELETE_FINGERPRINT = 0x0D,
  LOIRE_FPC_CAPTURE_IMAGE = 0x0E,
  LOIRE_FPC_SET_GID = 0x0F,
  LOIRE_FPC_GET_TEMPLATE_ID = 0x10,
  LOIRE_FPC_INIT = 0x11,
  LOIRE_FPC_PRINT_INFO = 0x12,
};

enum fingerprint_loire_fpcdata_cmd_t {
  LOIRE_FPC_SET_AUTH_CHALLENGE = 0x01,
  LOIRE_FPC_GET_AUTH_CHALLENGE = 0x02,
  LOIRE_FPC_AUTHORIZE_ENROL = 0x03,
  LOIRE_FPC_GET_AUTH_RESULT = 0x04,
  LOIRE_FPC_SET_KEY_DATA= 0x05,
};

enum fingerprint_loire_db_cmd_t {
  LOIRE_FPC_LOAD_DB = 0x0A,
  LOIRE_FPC_STORE_DB = 0x0B,
};

enum fingerprint_loire_debug_cmd_t {
  LOIRE_FPC_GET_SENSOR_INFO = 0x03,
};

static struct tz_command_list_t loire_commands = {
 .fpc_begin_enrol = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_BEGIN_ENROL},
 .fpc_enrol_step = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_ENROL_STEP},
 .fpc_end_enrol = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_END_ENROL},
 .fpc_identify = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_IDENTIFY},
 .fpc_wait_for_finger_lost = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_WAIT_FINGER_LOST},
 .fpc_wait_for_finger_down = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_WAIT_FINGER_DOWN},
 .fpc_get_finger_status = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_GET_FINGER_STATUS},
 .fpc_load_empty_db = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_LOAD_EMPTY_DB},
 .fpc_get_fingerprints = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_GET_FINGERPRINTS},
 .fpc_delete_fingerprints = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_DELETE_FINGERPRINT},
 .fpc_capture_image = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_CAPTURE_IMAGE},
 .fpc_set_gid = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_SET_GID},
 .fpc_get_template_id = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_GET_TEMPLATE_ID},
 .fpc_init = {LOIRE_FPC_GROUP_NORMAL, LOIRE_FPC_INIT},
 .fpc_set_auth_challenge = {LOIRE_FPC_GROUP_FPCDATA, LOIRE_FPC_SET_AUTH_CHALLENGE},
 .fpc_get_auth_challenge = {LOIRE_FPC_GROUP_FPCDATA, LOIRE_FPC_GET_AUTH_CHALLENGE},
 .fpc_auth_enrol = {LOIRE_FPC_GROUP_FPCDATA, LOIRE_FPC_AUTHORIZE_ENROL},
 .fpc_get_auth_result = {LOIRE_FPC_GROUP_FPCDATA, LOIRE_FPC_GET_AUTH_RESULT},
 .fpc_set_key_data = {LOIRE_FPC_GROUP_FPCDATA, LOIRE_FPC_SET_KEY_DATA},
 .fpc_load_db = {LOIRE_FPC_GROUP_DB, LOIRE_FPC_LOAD_DB},
 .fpc_store_db = {LOIRE_FPC_GROUP_DB, LOIRE_FPC_STORE_DB},
 .tz_response_offset = 64,
 .tz_imp_name = "Loire 6.x FPC (Hybrid)",
};

#ifdef __cplusplus
}
#endif
#endif
