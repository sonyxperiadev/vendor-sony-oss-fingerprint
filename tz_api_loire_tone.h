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

#ifndef _TZAPI_LOIRE_TONE_H_
#define _TZAPI_LOIRE_TONE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FP_TZAPP_PATH "/vendor/firmware/"
#define FP_TZAPP_NAME "tzfingerprint"

#define KM_TZAPP_PATH "/firmware/image/"
#define KM_TZAPP_NAME "keymaste"
#define KM_TZAPP_ALT_NAME "keymaster"

#define BUFFER_SIZE 64
#define FINGERPRINT_MAX_COUNT 5
#define AUTH_RESULT_LENGTH 69

typedef struct tz_command_t {
  uint32_t group_id;
  uint32_t cmd_id;
} tz_command_t;

typedef struct tz_command_list_t {
  struct tz_command_t fpc_begin_enrol;
  struct tz_command_t fpc_enrol_step;
  struct tz_command_t fpc_end_enrol;
  struct tz_command_t fpc_identify;
  struct tz_command_t fpc_wait_for_finger_lost;
  struct tz_command_t fpc_wait_for_finger_down;
  struct tz_command_t fpc_get_finger_status;
  struct tz_command_t fpc_load_empty_db;
  struct tz_command_t fpc_get_fingerprints;
  struct tz_command_t fpc_delete_fingerprints;
  struct tz_command_t fpc_capture_image;
  struct tz_command_t fpc_set_gid;
  struct tz_command_t fpc_get_template_id;
  struct tz_command_t fpc_init;
  struct tz_command_t fpc_set_auth_challenge;
  struct tz_command_t fpc_get_auth_challenge;
  struct tz_command_t fpc_auth_enrol;
  struct tz_command_t fpc_get_auth_result;
  struct tz_command_t fpc_set_key_data;
  struct tz_command_t fpc_load_db;
  struct tz_command_t fpc_store_db;
  int tz_response_offset;
  char* tz_imp_name;
} tz_command_list_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint32_t ret_val; //Some cases this is used for return value of the command
} fpc_send_std_cmd_t;

typedef struct {
    uint32_t cmd_id;
    uint32_t ret_val; //Some cases this is used for return value of the command
    uint32_t length; //Some length of data supplied by previous modified command
} keymaster_cmd_t;


typedef struct {
  int32_t status;
  uint32_t offset;
  uint32_t length;
} keymaster_return_t;


typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint64_t challenge;
    int32_t status;
} fpc_send_auth_cmd_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint32_t gid;
    int32_t status;
} fpc_set_gid_t;

typedef struct {
  uint32_t group_id;
  uint32_t cmd_id;
  int32_t status;
  uint32_t length;
  char data[];
} fpc_send_keydata_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint64_t challenge;
    int32_t status;
} fpc_load_auth_challenge_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    int32_t status;
    uint32_t remaining_touches;
} fpc_enrol_step_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint32_t print_id;
    int32_t status;
} fpc_end_enrol_t;

typedef struct {
  uint32_t group_id;
  uint32_t cmd_id;
  int32_t status;
  uint32_t length;
  char* data;
} fpc_send_buffer_t;

typedef struct {
  uint32_t commandgroup;
  uint32_t command;
  int32_t status;
  uint32_t id;
  uint32_t dbg1;
  uint32_t dbg2;
} fpc_send_identify_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    int32_t status;
    uint32_t length;
    uint32_t fingerprints[FINGERPRINT_MAX_COUNT];
} fpc_fingerprint_list_t;


typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint32_t fingerprint_id;
    int32_t status;
} fpc_fingerprint_delete_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint32_t result;
    uint32_t length;
    uint8_t auth_result[AUTH_RESULT_LENGTH]; // In practice this is always 69 bytes
} fpc_get_auth_result_t;

typedef struct {
    uint32_t length; //Length of data on ion buffer
    uint32_t v_addr; //Virtual address of ion mmap buffer
} fpc_send_mod_cmd_t;

typedef struct {
    uint32_t group_id;
    uint32_t cmd_id;
    uint32_t result;
    uint32_t auth_id;
} fpc_get_db_id_cmd_t;


#endif /* __TZAPI_LOIRE_TONE_H_ */
