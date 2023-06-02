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

#include "UInput.h"
#include "common.h"

#include <stdbool.h>
#include <stdint.h>

#define MAX_FINGERPRINTS 5
typedef struct
{
    uint32_t print_count;
    uint32_t prints[MAX_FINGERPRINTS];
} fpc_fingerprint_index_t;

struct fpc_imp_data {
    fpc_event_t event;
    fpc_uinput_t uinput;
};

int64_t fpc_load_db_id(struct fpc_imp_data *data);                                     // load db ID, used as authenticator ID in android
int64_t fpc_load_auth_challenge(struct fpc_imp_data *data);                            // genertate and load an auth challenge for pre enroll
err_t fpc_set_auth_challenge(struct fpc_imp_data *data, int64_t challenge);            // set auth challenge during authenticate
err_t fpc_verify_auth_challenge(struct fpc_imp_data *data, void *hat, uint32_t size);  // verify auth challenge before enroll (ensure its still valid)
err_t fpc_get_hw_auth_obj(struct fpc_imp_data *data, void *buffer, uint32_t length);   // get HAT object (copied into buffer) on authenticate
// FIXME: This should probably only exist inside kitakami implementation?
// Make all functions return resolved index->id
// FIXME: Internal to kitakami:
err_t fpc_get_print_id(struct fpc_imp_data *data, int id);
err_t fpc_del_print_id(struct fpc_imp_data *data, uint32_t id);                           // delete print at index
fpc_fingerprint_index_t fpc_get_print_ids(struct fpc_imp_data *data, uint32_t count);     // get list of print index's available
err_t fpc_get_print_index(struct fpc_imp_data *data, fpc_fingerprint_index_t *idx_data);  // get list of print index's available
err_t fpc_wait_for_finger(struct fpc_imp_data *data);                                     // wait for event IRQ on print reader
err_t fpc_capture_image(struct fpc_imp_data *data);                                       // capture image ready for enroll / auth
err_t fpc_enroll_step(struct fpc_imp_data *data, uint32_t *remaining_touches);            // step forward enroll & process image (only available if capture image returns OK)
// FIXME: index of next print should be retrieved using fpc_get-print_count internally in kitakami impl.
err_t fpc_enroll_start(struct fpc_imp_data *data, int print_index);   // start enrollment
err_t fpc_enroll_end(struct fpc_imp_data *data, uint32_t *print_id);  // end enrollment
err_t fpc_auth_start(struct fpc_imp_data *data);                      // start auth
err_t fpc_auth_step(struct fpc_imp_data *data, uint32_t *print_id);   // step forward auth & process image (only available if capture image returns OK)
err_t fpc_auth_end(struct fpc_imp_data *data);                        // end auth
err_t fpc_update_template(struct fpc_imp_data *data);                 // Update fingerprint template
err_t fpc_set_gid(struct fpc_imp_data *data, uint32_t gid);
err_t fpc_load_user_db(struct fpc_imp_data *data, char *path);  // load user DB into TZ app from storage
err_t fpc_load_empty_db(struct fpc_imp_data *data);
err_t fpc_store_user_db(struct fpc_imp_data *data, char *path);  // store running TZ db
err_t fpc_close(struct fpc_imp_data **data);                     // close this implementation
err_t fpc_init(struct fpc_imp_data **data, int event_fd);        // init sensor

bool fpc_navi_supported(struct fpc_imp_data *data);
err_t fpc_navi_enter(struct fpc_imp_data *data);
err_t fpc_navi_exit(struct fpc_imp_data *data);
err_t fpc_navi_poll(struct fpc_imp_data *data);

#endif
