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

#ifndef __FPCIMPL_H_
#define __FPCIMPL_H_

#include <stdbool.h>
#include <stdint.h>
#include "common.h"

#define MAX_FINGERPRINTS 5
typedef struct
{
    uint32_t print_count;
    uint32_t prints[MAX_FINGERPRINTS];
} fpc_fingerprint_index_t;

typedef struct fpc_imp_data_t {

} fpc_imp_data_t;

typedef struct fpc_imp_func_t {
    char* (*fpc_get_name) (fpc_imp_data_t *data);
    int64_t (*fpc_load_db_id) (fpc_imp_data_t *data); //load db ID, used as authenticator ID in android
    int64_t (*fpc_load_auth_challenge) (fpc_imp_data_t *data); //genertate and load an auth challenge for pre enroll
    err_t (*fpc_set_auth_challenge) (fpc_imp_data_t *data, int64_t challenge); //set auth challenge during authenticate
    err_t (*fpc_verify_auth_challenge) (fpc_imp_data_t *data, void* hat, uint32_t size); //verify auth challenge before enroll (ensure its still valid)
    err_t (*fpc_get_hw_auth_obj) (fpc_imp_data_t *data, void * buffer, uint32_t length); //get HAT object (copied into buffer) on authenticate
    // FIXME: This should probably only exist inside kitakami implementation?
    // Make all functions return resolved index->id
    // FIXME: Internal to kitakami:
    err_t (*fpc_get_print_count) (fpc_imp_data_t *data); //get count of enrolled prints
    err_t (*fpc_del_print_id) (fpc_imp_data_t *data, uint32_t id); //delete print at index
    fpc_fingerprint_index_t (*fpc_get_print_index) (fpc_imp_data_t *data, uint32_t count); //get list of print index's available
    err_t (*fpc_capture_image) (fpc_imp_data_t *data); //capture image ready for enroll / auth
    err_t (*fpc_enroll_step) (fpc_imp_data_t *data, uint32_t *remaining_touches); //step forward enroll & process image (only available if capture image returns OK)
    // FIXME: index of next print should be retrieved using fpc_get-print_count internally in kitakami impl.
    err_t (*fpc_enroll_start) (fpc_imp_data_t *data, int print_index); //start enrollment
    err_t (*fpc_enroll_end) (fpc_imp_data_t *data, uint32_t *print_id); //end enrollment
    err_t (*fpc_auth_start) (fpc_imp_data_t *data); //start auth
    err_t (*fpc_auth_step) (fpc_imp_data_t *data, uint32_t *print_id); //step forward auth & process image (only available if capture image returns OK)
    err_t (*fpc_auth_end) (fpc_imp_data_t *data); //end auth
    // FIXME: This should be internal to kitakami implementation
    err_t (*fpc_get_user_db_length) (fpc_imp_data_t *data); //get size of working db
    err_t (*fpc_set_gid) (fpc_imp_data_t *data, uint32_t gid);
    err_t (*fpc_load_user_db) (fpc_imp_data_t *data, char* path); //load user DB into TZ app from storage
    err_t (*fpc_load_empty_db) (fpc_imp_data_t *data);
    // FIXME: length should be fetched internally in kitakami implementation
    err_t (*fpc_store_user_db) (fpc_imp_data_t *data, uint32_t length, char* path); //store running TZ db
    err_t (*fpc_close) (fpc_imp_data_t **data); //close this implementation
    err_t (*fpc_init) (fpc_imp_data_t **data); //init sensor

    //Implementation selectors
    bool per_db_gid;

} fpc_imp_func_t;

//per plaform function init
void fpc_kitakami_init_func(fpc_imp_func_t **func);
void fpc_loire_init_func(fpc_imp_func_t **func);
void fpc_tone_init_func(fpc_imp_func_t **func);
void fpc_yoshino_init_func(fpc_imp_func_t **func);

#endif
