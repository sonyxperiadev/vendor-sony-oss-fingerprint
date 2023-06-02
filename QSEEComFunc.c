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

#include "QSEEComFunc.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "QSEE_WRAPPER"
// #define LOG_NDEBUG 0

// #define USE_QSEE_WRAPPER 1
#ifdef USE_QSEE_WRAPPER
#define QSEE_LIBRARY "libDSEEComAPI.so"
#else
#define QSEE_LIBRARY "libQSEEComAPI.so"
#endif

#include <log/log.h>

// Forward declarations

static int qsee_load_trustlet(struct qsee_handle *qsee_handle,
                              struct QSEECom_handle **clnt_handle,
                              const char *path, const char *fname,
                              uint32_t sb_size);
char *qsee_error_strings(int err);
struct _priv_data {
    void *libHandle;
};

int32_t qsee_open_handle(struct qsee_handle **ret_handle) {
    struct qsee_handle *handle = NULL;
    struct _priv_data *data = NULL;
    int32_t ret = -1;

    ALOGD("Using Target Lib : %s\n", QSEE_LIBRARY);
    data = (struct _priv_data *)malloc(sizeof(struct _priv_data));
    if (data == NULL) {
        ALOGE("Error allocating memory: %s\n", strerror(errno));
        goto exit;
    }
    data->libHandle = dlopen(QSEE_LIBRARY, RTLD_NOW);
    if (data->libHandle == NULL) {
        ALOGE("Failed to load QSEECom API library: %s\n", strerror(errno));
        goto exit_err_data;
    }
    ALOGD("Loaded QSEECom API library at %p\n", data->libHandle);

    handle = (struct qsee_handle *)malloc(sizeof(struct qsee_handle));
    if (handle == NULL) {
        ALOGE("Error allocating memory: %s\n", strerror(errno));
        goto exit_err_dlhandle;
    }

    handle->_data = data;

    ALOGD("Loaded QSEECom API library...\n");
    // Setup internal functions
    handle->ion_alloc = qcom_km_ion_memalloc;
    handle->ion_free = qcom_km_ion_dealloc;
    handle->load_trustlet = qsee_load_trustlet;

    // Setup QSEECom Functions
    // NOTE: dlsym doesn't allocate anything, so there's nothing extra to free from these calls!

    handle->start_app = (start_app_def)dlsym(data->libHandle, "QSEECom_start_app");
    if (handle->start_app == NULL) {
        ALOGE("Error loading QSEECom_start_app: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->shutdown_app = (shutdown_app_def)dlsym(data->libHandle, "QSEECom_shutdown_app");
    if (handle->shutdown_app == NULL) {
        ALOGE("Error loading QSEECom_shutdown_app: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->load_external_elf = (load_external_elf_def)dlsym(data->libHandle, "QSEECom_load_external_elf");
    if (handle->load_external_elf == NULL) {
        ALOGE("Error loading QSEECom_load_external_elf: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->unload_external_elf = (unload_external_elf_def)dlsym(data->libHandle, "QSEECom_unload_external_elf");
    if (handle->unload_external_elf == NULL) {
        ALOGE("Error loading QSEECom_unload_external_elf: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->register_listener = (register_listener_def)dlsym(data->libHandle, "QSEECom_register_listener");
    if (handle->register_listener == NULL) {
        ALOGE("Error loading QSEECom_register_listener: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->unregister_listener = (unregister_listener_def)dlsym(data->libHandle, "QSEECom_unregister_listener");
    if (handle->unregister_listener == NULL) {
        ALOGE("Error loading QSEECom_unregister_listener: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->send_cmd = (send_cmd_def)dlsym(data->libHandle, "QSEECom_send_cmd");
    if (handle->send_cmd == NULL) {
        ALOGE("Error loading QSEECom_send_cmd: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->send_modified_cmd = (send_modified_cmd_def)dlsym(data->libHandle, "QSEECom_send_modified_cmd");
    if (handle->send_modified_cmd == NULL) {
        ALOGE("Error loading QSEECom_send_modified_cmd: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->receive_req = (receive_req_def)dlsym(data->libHandle, "QSEECom_receive_req");
    if (handle->receive_req == NULL) {
        ALOGE("Error loading QSEECom_receive_req: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->send_resp = (send_resp_def)dlsym(data->libHandle, "QSEECom_send_resp");
    if (handle->send_resp == NULL) {
        ALOGE("Error loading QSEECom_send_resp: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->set_bandwidth = (set_bandwidth_def)dlsym(data->libHandle, "QSEECom_set_bandwidth");
    if (handle->set_bandwidth == NULL) {
        ALOGE("Error loading QSEECom_set_bandwidth: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    handle->app_load_query = (app_load_query_def)dlsym(data->libHandle, "QSEECom_app_load_query");
    if (handle->app_load_query == NULL) {
        ALOGE("Error loading QSEECom_app_load_query: %s\n", strerror(errno));
        goto exit_err_handle;
    }

    *ret_handle = handle;
    return 0;

exit_err_handle:
    if (handle != NULL) {
        free(handle);
    }
exit_err_dlhandle:
    if (data->libHandle != NULL) {
        dlclose(data->libHandle);
        data->libHandle = NULL;
    }
exit_err_data:
    if (data != NULL)
        free(data);
exit:
    return ret;
}

int qsee_free_handle(struct qsee_handle **handle_ptr) {
    struct _priv_data *data = NULL;
    struct qsee_handle *handle;
    handle = *handle_ptr;
    data = (struct _priv_data *)handle->_data;

    dlclose(data->libHandle);
    free(data);
    free(handle);
    *handle_ptr = NULL;
    return 0;
}

char *qsee_error_strings(int err) {
    switch (err) {
        case QSEECOM_LISTENER_REGISTER_FAIL:
            return "QSEECom: Failed to register listener\n";
        case QSEECOM_LISTENER_ALREADY_REGISTERED:
            return "QSEECom: Listener already registered\n";
        case QSEECOM_LISTENER_UNREGISTERED:
            return "QSEECom: Listener unregistered\n";
        case QSEECOM_APP_ALREADY_LOADED:
            return "QSEECom: Trustlet already loaded\n";
        case QSEECOM_APP_NOT_LOADED:
            return "QSEECom: Trustlet not loaded\n";
        case QSEECOM_APP_QUERY_FAILED:
            return "QSEECom: Failed to query trustlet\n";
        default:
            return "QSEECom: Unknown error\n";
    }
}

int qsee_load_trustlet(struct qsee_handle *qsee_handle,
                       struct QSEECom_handle **clnt_handle,
                       const char *path, const char *fname,
                       uint32_t sb_size) {
    int ret = 0;
    char *errstr;
    int sz = sb_size;
    // Too small size causes failures, so force a reasonable size
    if (sz < 1024) {
        ALOGD("Warning: sb_size too small, increasing to avoid breakage");
        sz = 1024;
    }

    ALOGI("Starting app %s\n", fname);
    ret = qsee_handle->start_app(clnt_handle, path, fname, sz);
    if (ret < 0) {
        errstr = qsee_error_strings(ret);
        ALOGE("Could not load app %s. Error: %s (%d)\n",
              fname, errstr, ret);
    } else
        ALOGI("TZ App loaded: %s\n", fname);

    return ret;
}
