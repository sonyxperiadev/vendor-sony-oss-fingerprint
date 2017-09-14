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

#define LOG_TAG "AOSP FPC HAL"

#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <cutils/log.h>
#include <hardware/hardware.h>
#include <hardware/fingerprint.h>
#include <inttypes.h>
#include <pthread.h>
#include <netinet/in.h>
#include <byteswap.h>
#include <sys/stat.h>
#include "fpc_imp.h"


typedef struct {
    pthread_t thread;
    bool thread_running;
} fpc_thread_t;

typedef struct {
    fingerprint_device_t device;  // "inheritance"
    fpc_thread_t worker;
    fpc_imp_data_t *fpc;
    uint32_t gid;
    char db_path[255];
    pthread_mutex_t lock;
    uint64_t challenge;
} sony_fingerprint_device_t;

void *enroll_thread_loop(void *arg)
{
    ALOGI("%s", __func__);
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)arg;
    fingerprint_notify_t callback = sdev->device.notify;

    int32_t print_count = fpc_get_print_count(sdev->fpc);
    ALOGD("%s : print count is : %u", __func__, print_count);

    int ret = fpc_enroll_start(sdev->fpc, print_count);
    if(ret < 0)
    {
        ALOGE("Starting enrol failed: %d\n", ret);
    }

    int status = 1;

    while((status = fpc_capture_image(sdev->fpc)) >= 0) {
        ALOGD("%s : Got Input status=%d", __func__, status);

        pthread_mutex_lock(&sdev->lock);
        if (!sdev->worker.thread_running ) {
            pthread_mutex_unlock(&sdev->lock);
            ALOGI("%s : finishing",__func__);
            return NULL;
        }
        pthread_mutex_unlock(&sdev->lock);

        if(status >= 1000)
            continue;
        
        if (status <= FINGERPRINT_ACQUIRED_TOO_FAST) {
            fingerprint_msg_t msg;
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = status;
            callback(&msg);
        }

        //image captured
        if (status == FINGERPRINT_ACQUIRED_GOOD) {
            ALOGI("%s : Enroll Step", __func__);
            uint32_t remaining_touches = 0;
            int ret = fpc_enroll_step(sdev->fpc, &remaining_touches);
            ALOGE("%s: step: %d, touches=%d\n", __func__, ret, remaining_touches);
            if (ret > 0) {
                ALOGI("%s : Touches Remaining : %d", __func__, remaining_touches);
                if (remaining_touches > 0) {
                    fingerprint_msg_t msg;
                    msg.type = FINGERPRINT_TEMPLATE_ENROLLING;
                    msg.data.enroll.finger.fid = 0;
                    msg.data.enroll.finger.gid = 0;
                    msg.data.enroll.samples_remaining = remaining_touches;
                    msg.data.enroll.msg = 0;
                    callback(&msg);
                }
            }
            else if (ret == 0) {

                uint32_t print_id = 0;
                int print_index = fpc_enroll_end(sdev->fpc, &print_id);

                if (print_index < 0){
                    ALOGE("%s : Error getting new print index : %d", __func__,print_index);
                    fingerprint_msg_t msg;
                    msg.type = FINGERPRINT_ERROR;
                    msg.data.error = FINGERPRINT_ERROR_UNABLE_TO_PROCESS;
                    callback(&msg);
                    break;
                }

                uint32_t db_length = fpc_get_user_db_length(sdev->fpc);
                ALOGI("%s : User Database Length Is : %lu", __func__,(unsigned long) db_length);
                fpc_store_user_db(sdev->fpc, db_length, sdev->db_path);

                ALOGI("%s : Got print id : %lu", __func__,(unsigned long) print_id);

                fingerprint_msg_t msg;
                msg.type = FINGERPRINT_TEMPLATE_ENROLLING;
                msg.data.enroll.finger.fid = print_id;
                msg.data.enroll.finger.gid = sdev->gid;
                msg.data.enroll.samples_remaining = 0;
                msg.data.enroll.msg = 0;
                callback(&msg);
                break;
            }
            else {
                ALOGE("Error in enroll step, aborting enroll: %d\n", ret);
                fingerprint_msg_t msg;
                msg.type = FINGERPRINT_ERROR;
                msg.data.error = FINGERPRINT_ERROR_UNABLE_TO_PROCESS;
                callback(&msg);
                break;
            }
        }
    }

    pthread_mutex_lock(&sdev->lock);
    sdev->worker.thread_running = false;
    pthread_mutex_unlock(&sdev->lock);

    ALOGI("%s : finishing",__func__);

    return NULL;
}


void *auth_thread_loop(void *arg)
{
    ALOGI("%s", __func__);

    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)arg;
    fingerprint_notify_t callback = sdev->device.notify;

    fpc_auth_start(sdev->fpc);

    int status = 1;

    while((status = fpc_capture_image(sdev->fpc)) >= 0 ) {
        ALOGD("%s : Got Input with status %d", __func__, status);

        pthread_mutex_lock(&sdev->lock);
        if (!sdev->worker.thread_running ) {
            pthread_mutex_unlock(&sdev->lock);
            fpc_auth_end(sdev->fpc);
            break;
        }
        pthread_mutex_unlock(&sdev->lock);

        if(status >= 1000)
            continue;

        if (status <= FINGERPRINT_ACQUIRED_TOO_FAST) {
            fingerprint_msg_t msg;
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = status;
            callback(&msg);
        }

        if (status == FINGERPRINT_ACQUIRED_GOOD) {

            uint32_t print_id = 0;
            int verify_state = fpc_auth_step(sdev->fpc, &print_id);
            ALOGI("%s : Auth step = %d", __func__, verify_state);

            if (verify_state >= 0) {
                if(print_id > 0)
                {
                    ALOGI("%s : Got print id : %u", __func__, print_id);

                    hw_auth_token_t hat;
                    fpc_get_hw_auth_obj(sdev->fpc, &hat, sizeof(hw_auth_token_t));

                    ALOGI("%s : hat->challenge %" PRIu64, __func__, hat.challenge);
                    ALOGI("%s : hat->user_id %" PRIu64, __func__, hat.user_id);
                    ALOGI("%s : hat->authenticator_id %" PRIu64, __func__, hat.authenticator_id);
                    ALOGI("%s : hat->authenticator_type %u", __func__, ntohl(hat.authenticator_type));
                    ALOGI("%s : hat->timestamp %" PRIu64, __func__, bswap_64(hat.timestamp));
                    ALOGI("%s : hat size %zu", __func__, sizeof(hw_auth_token_t));

                    fingerprint_msg_t msg;
                    msg.type = FINGERPRINT_AUTHENTICATED;
                    msg.data.authenticated.finger.gid = sdev->gid;
                    msg.data.authenticated.finger.fid = print_id;

                    msg.data.authenticated.hat = hat;

                    callback(&msg);

                    fpc_auth_end(sdev->fpc);
                    pthread_mutex_lock(&sdev->lock);
                    sdev->worker.thread_running  = false;
                    pthread_mutex_unlock(&sdev->lock);
                    break;
                }
            }
            fingerprint_msg_t msg;
            msg.type = FINGERPRINT_AUTHENTICATED;
            msg.data.authenticated.finger.fid = 0;
            callback(&msg);
        }
    }

    ALOGI("%s : finishing",__func__);

    return NULL;
}

static int fingerprint_close(hw_device_t *dev)
{
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;
    fpc_close(&sdev->fpc);
    if (dev) {
        free(dev);
        return 0;
    } else {
        return -1;
    }
}

static uint64_t fingerprint_pre_enroll(struct fingerprint_device *dev)
{
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;
    sdev->challenge = fpc_load_auth_challenge(sdev->fpc);
    ALOGI("%s : Challenge is : %jd",__func__, sdev->challenge);
    return sdev->challenge;
}

static int fingerprint_enroll(struct fingerprint_device *dev,
                              const hw_auth_token_t *hat,
                              uint32_t __attribute__((unused)) gid,
                              uint32_t __attribute__((unused)) timeout_sec)
{
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;

    pthread_mutex_lock(&sdev->lock);
    if (sdev->worker.thread_running) {
        pthread_mutex_unlock(&sdev->lock);
        ALOGE("%s : Error, thread already running\n", __func__);
        return -1;
    }
    pthread_mutex_unlock(&sdev->lock);

    ALOGI("%s : hat->challenge %lu",__func__,(unsigned long) hat->challenge);
    ALOGI("%s : hat->user_id %lu",__func__,(unsigned long) hat->user_id);
    ALOGI("%s : hat->authenticator_id %lu",__func__,(unsigned long) hat->authenticator_id);
    ALOGI("%s : hat->authenticator_type %d",__func__,hat->authenticator_type);
    ALOGI("%s : hat->timestamp %lu",__func__,(unsigned long) hat->timestamp);
    ALOGI("%s : hat size %lu",__func__,(unsigned long) sizeof(hw_auth_token_t));

    fpc_verify_auth_challenge(sdev->fpc, (void*) hat, sizeof(hw_auth_token_t));

    pthread_mutex_lock(&sdev->lock);
    sdev->worker.thread_running  = true;
    pthread_mutex_unlock(&sdev->lock);

    if(pthread_create(&sdev->worker.thread, NULL, enroll_thread_loop, (void*)sdev)) {
        sdev->worker.thread_running  = false;
        ALOGE("%s : Error creating thread\n", __func__);
        return FINGERPRINT_ERROR;
    }

    return 0;

}

static uint64_t fingerprint_get_auth_id(struct fingerprint_device *dev)
{
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;
    uint64_t id = fpc_load_db_id(sdev->fpc);
    ALOGI("%s : ID : %jd",__func__,id );
    return id;

}

static int fingerprint_cancel(struct fingerprint_device *dev)
{
    ALOGI("%s : +",__func__);
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;
    
    ALOGI("%s : check thread running",__func__);
    pthread_mutex_lock(&sdev->lock);
    if (!sdev->worker.thread_running ) {
        pthread_mutex_unlock(&sdev->lock);
        ALOGI("%s : - (thread not running)",__func__);
        return 0;
    }
    sdev->worker.thread_running  = false;
    pthread_mutex_unlock(&sdev->lock);

    ALOGI("%s : join running thread",__func__);
    pthread_join(sdev->worker.thread, NULL);

    ALOGI("%s : -",__func__);

    /*fingerprint_msg_t msg;
    msg.type = FINGERPRINT_ERROR;
    msg.data.error = FINGERPRINT_ERROR_CANCELED;
    callback(&msg);*/

    return 0;
}

static int fingerprint_remove(struct fingerprint_device  *dev,
                              uint32_t gid, uint32_t fid)
{
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;
    fingerprint_notify_t callback = sdev->device.notify;

    if (fpc_del_print_id(sdev->fpc, fid) == 0){
        fingerprint_msg_t msg;
        msg.type = FINGERPRINT_TEMPLATE_REMOVED;
        msg.data.removed.finger.fid = fid;
        msg.data.removed.finger.gid = gid;
        callback(&msg);

        uint32_t db_length = fpc_get_user_db_length(sdev->fpc);
        ALOGD("%s : User Database Length Is : %lu", __func__,(unsigned long) db_length);
        fpc_store_user_db(sdev->fpc, db_length, sdev->db_path);
        return 0;
    } else {
        fingerprint_msg_t msg;
        msg.type = FINGERPRINT_ERROR;
        msg.data.error = FINGERPRINT_ERROR_UNABLE_TO_REMOVE;
        callback(&msg);

        return FINGERPRINT_ERROR;
    }
}

static int fingerprint_set_active_group(struct fingerprint_device *dev,
                                        uint32_t gid, const char *store_path)
{
    int result;
    struct stat sb;
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;

    #ifdef FPC_DB_PER_GID
    sprintf(sdev->db_path,"%s/data_%d.db", store_path, gid);
    #else
    sprintf(sdev->db_path,"%s/user.db", store_path);
    #endif
    sdev->gid = gid;

    ALOGI("%s : storage path set to : %s",__func__, sdev->db_path);
    if(stat(sdev->db_path, &sb) == -1) {
        // No existing database, load an empty one
        fpc_load_empty_db(sdev->fpc);
        int length  = fpc_get_user_db_length(sdev->fpc);
        fpc_store_user_db(sdev->fpc, length, sdev->db_path);

        return 0;
    } else {
        if ((result = fpc_load_user_db(sdev->fpc, sdev->db_path)) != 0) {
            ALOGE("Error loading user database: %d\n", result);
            return result;
        }
    }

    if((result = fpc_set_gid(sdev->fpc, gid)) != 0)
    {
        ALOGE("Error setting current gid: %d\n", result);
    }
    return result;

}

#if PLATFORM_SDK_VERSION >= 24
static int fingerprint_enumerate(struct fingerprint_device *dev)
{
    ALOGE(__func__);
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;
    fingerprint_notify_t callback = sdev->device.notify;

    uint32_t print_count = fpc_get_print_count(sdev->fpc);
    ALOGD("%s : print count is : %u", __func__, print_count);

    fpc_fingerprint_index_t print_indexs = fpc_get_print_index(sdev->fpc, print_count);
    if(print_indexs.print_count != print_count)
    {
        ALOGW("Print count mismatch: %d != %d", print_count, print_indexs.print_count);
    }

    for (size_t i = 0; i < print_indexs.print_count; i++) {
        ALOGD("%s : found print : %lu at index %zu", __func__, (unsigned long) print_indexs.prints[i], i);
        fingerprint_msg_t msg;
        msg.type = FINGERPRINT_TEMPLATE_ENUMERATING;
        msg.data.enumerated.finger.fid = print_indexs.prints[i];
        msg.data.enumerated.finger.gid = sdev->gid;
        msg.data.enumerated.remaining_templates = (uint32_t)(print_indexs.print_count - i - 1);
        callback(&msg);
    }
    return 0;
}
#else
static int fingerprint_enumerate(struct fingerprint_device *dev,
                                 fingerprint_finger_id_t *results,
                                 uint32_t *max_size)
{
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;

    uint32_t print_count = fpc_get_print_count(sdev->fpc);
    ALOGD("%s : print count is : %u", __func__, print_count);
    fpc_fingerprint_index_t print_indexs = fpc_get_print_index(sdev->fpc, print_count);

    if (*max_size == 0) {
        *max_size = print_count;
    } else {
        for (size_t i = 0; i < *max_size && i < print_indexs.print_count; i++) {
            ALOGD("%s : found print : %lu at index %zu", __func__,(unsigned long) print_indexs.prints[i], i);

            results[i].fid = print_indexs.prints[i];
            results[i].gid = sdev->gid;
        }
    }

    return print_count;
}
#endif

static int fingerprint_authenticate(struct fingerprint_device __attribute__((unused)) *dev,
                                    uint64_t __attribute__((unused)) operation_id, __attribute__((unused)) uint32_t gid)
{

    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;

    pthread_mutex_lock(&sdev->lock);
    if (sdev->worker.thread_running) {
        pthread_mutex_unlock(&sdev->lock);
        ALOGE("%s : Error, thread already running\n", __func__);
        return -1;
    }
    sdev->worker.thread_running = true;
    pthread_mutex_unlock(&sdev->lock);

    if(pthread_create(&sdev->worker.thread, NULL, auth_thread_loop, (void*)sdev)) {
        sdev->worker.thread_running = false;
        ALOGE("%s : Error creating thread\n", __func__);
        return FINGERPRINT_ERROR;
    }

    return 0;
}

static int set_notify_callback(struct fingerprint_device *dev,
                               fingerprint_notify_t notify)
{
    sony_fingerprint_device_t *sdev = (sony_fingerprint_device_t*)dev;
    pthread_mutex_lock(&sdev->lock);
    dev->notify = notify;
    pthread_mutex_unlock(&sdev->lock);
    return 0;
}

static int fingerprint_open(const hw_module_t* module, const char __attribute__((unused)) *id,
                            hw_device_t** device)
{

    ALOGI("%s",__func__);

    if (device == NULL) {
        ALOGE("NULL device on open");
        return -EINVAL;
    }
    fpc_imp_data_t *fpc_data = NULL;

    if (fpc_init(&fpc_data) < 0) {
        ALOGE("Could not init FPC device");
        return -EINVAL;
    }

    sony_fingerprint_device_t *sdev = malloc(sizeof(sony_fingerprint_device_t));
    fingerprint_device_t *dev = (fingerprint_device_t*)sdev;

    memset(sdev, 0, sizeof(sony_fingerprint_device_t));
    sdev->fpc = fpc_data;

    dev->common.tag = HARDWARE_DEVICE_TAG;
#if PLATFORM_SDK_VERSION >= 24
    dev->common.version = FINGERPRINT_MODULE_API_VERSION_2_1;
#else
    dev->common.version = FINGERPRINT_MODULE_API_VERSION_2_0;
#endif
    dev->common.module = (struct hw_module_t*) module;
    dev->common.close = fingerprint_close;

    dev->pre_enroll = fingerprint_pre_enroll;
    dev->enroll = fingerprint_enroll;
    dev->get_authenticator_id = fingerprint_get_auth_id;
    dev->cancel = fingerprint_cancel;
    dev->remove = fingerprint_remove;
    dev->set_active_group = fingerprint_set_active_group;
    dev->enumerate = fingerprint_enumerate;
    dev->authenticate = fingerprint_authenticate;
    dev->set_notify = set_notify_callback;
    dev->notify = NULL;

    *device = (hw_device_t*) dev;
    return 0;
}

static struct hw_module_methods_t fingerprint_module_methods = {
    .open = fingerprint_open,
};

fingerprint_module_t HAL_MODULE_INFO_SYM = {
    .common = {
        .tag                = HARDWARE_MODULE_TAG,
#if PLATFORM_SDK_VERSION >= 24
        .module_api_version = FINGERPRINT_MODULE_API_VERSION_2_1,
#else
        .module_api_version = FINGERPRINT_MODULE_API_VERSION_2_0,
#endif
        .hal_api_version    = HARDWARE_HAL_API_VERSION,
        .id                 = FINGERPRINT_HARDWARE_MODULE_ID,
        .name               = "Kitakami Fingerprint HAL",
        .author             = "Shane Francis / Jens Andersen",
        .methods            = &fingerprint_module_methods,
    },
};
