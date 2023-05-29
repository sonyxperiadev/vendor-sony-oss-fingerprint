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

#include "QSEEComAPI.h"
#include "QSEEComFunc.h"
#include "common.h"
#include "fpc_imp.h"
#include "tz_api_loire_tone.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define LOG_TAG "FPC IMP"
// #define LOG_NDEBUG 0

#include <limits.h>
#include <log/log.h>

typedef struct {
    struct fpc_imp_data data;
    struct QSEECom_handle *fpc_handle;
    struct qsee_handle *qsee_handle;
    struct dmabuf_handle dhandle;
    uint64_t auth_id;
} fpc_data_t;

static const char *fpc_error_str(int err) {
    int realerror = err + 10;

    switch (realerror) {
        case 0:
            return "FPC_ERROR_CONFIG";
        case 1:
            return "FPC_ERROR_HARDWARE";
        case 2:
            return "FPC_ERROR_NOENTITY";
        case 3:
            return "FPC_ERROR_CANCELLED";
        case 4:
            return "FPC_ERROR_IO";
        case 5:
            return "FPC_ERROR_NOSPACE";
        case 6:
            return "FPC_ERROR_COMM";
        case 7:
            return "FPC_ERROR_ALLOC";
        case 8:
            return "FPC_ERROR_TIMEDOUT";
        case 9:
            return "FPC_ERROR_INPUT";
        default:
            return "FPC_ERROR_UNKNOWN";
    }
}

err_t send_modified_command_to_tz(fpc_data_t *ldata, struct dmabuf_handle dhandle) {
    struct QSEECom_handle *handle = ldata->fpc_handle;

    fpc_send_mod_cmd_t *send_cmd = (fpc_send_mod_cmd_t *)handle->ion_sbuffer;
    void *rec_cmd = handle->ion_sbuffer + TZ_RESPONSE_OFFSET;
    struct QSEECom_ion_fd_info ion_fd_info;

    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));

    ion_fd_info.data[0].fd = dhandle.fd;
    ion_fd_info.data[0].cmd_buf_offset = 4;

    send_cmd->v_addr = (intptr_t)dhandle.map;
    uint32_t length = (dhandle.len + 4095) & (~4095);
    send_cmd->length = length;
    int result = ldata->qsee_handle->send_modified_cmd(handle, send_cmd, 64, rec_cmd, 64, &ion_fd_info);

    if (result) {
        ALOGE("Error sending modified command: %d\n", result);
        return -1;
    }
    if ((result = *(int32_t *)rec_cmd) != 0) {
        ALOGE("Error in tz command (%d) : %s\n", result, fpc_error_str(result));
        return -2;
    }

    return result;
}

err_t send_normal_command(fpc_data_t *ldata, int command) {
    fpc_send_std_cmd_t *send_cmd =
        (fpc_send_std_cmd_t *)ldata->dhandle.map;

    send_cmd->group_id = 0x1;
    send_cmd->cmd_id = command;
    send_cmd->ret_val = 0x0;

    int ret = send_modified_command_to_tz(ldata, ldata->dhandle);

    if (!ret) {
        ret = send_cmd->ret_val;
    }

    return ret;
}

err_t send_buffer_command(fpc_data_t *ldata, uint32_t group_id, uint32_t cmd_id, const uint8_t *buffer, uint32_t length) {
    struct dmabuf_handle dhandle;
    if (ldata->qsee_handle->dmabuf_alloc(ldata->qsee_handle, &dhandle, length + sizeof(fpc_send_buffer_t)) < 0) {
        ALOGE("DMABUF allocation failed");
        return -1;
    }
    fpc_send_buffer_t *cmd_data = (fpc_send_buffer_t *)dhandle.map;
    memset(dhandle.map, 0, length + sizeof(fpc_send_buffer_t));
    cmd_data->group_id = group_id;
    cmd_data->cmd_id = cmd_id;
    cmd_data->length = length;
    memcpy(&cmd_data->data, buffer, length);

    if (send_modified_command_to_tz(ldata, dhandle) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    int result = cmd_data->status;
    ldata->qsee_handle->dmabuf_free(&dhandle);
    return result;
}

err_t send_command_result_buffer(fpc_data_t *ldata, uint32_t group_id, uint32_t cmd_id, uint8_t *buffer, uint32_t length) {
    struct dmabuf_handle dhandle;
    if (ldata->qsee_handle->dmabuf_alloc(ldata->qsee_handle, &dhandle, length + sizeof(fpc_send_buffer_t)) < 0) {
        ALOGE("DMABUF allocation failed");
        return -1;
    }
    fpc_send_buffer_t *keydata_cmd = (fpc_send_buffer_t *)dhandle.map;
    memset(dhandle.map, 0, length + sizeof(fpc_send_buffer_t));
    keydata_cmd->group_id = group_id;
    keydata_cmd->cmd_id = cmd_id;
    keydata_cmd->length = length;

    if (send_modified_command_to_tz(ldata, dhandle) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }
    memcpy(buffer, &keydata_cmd->data[0], length);

    int result = keydata_cmd->status;
    ldata->qsee_handle->dmabuf_free(&dhandle);
    return result;
}

err_t send_custom_cmd(fpc_data_t *ldata, void *buffer, uint32_t len) {
    ALOGV(__func__);
    struct dmabuf_handle dhandle;

    if (ldata->qsee_handle->dmabuf_alloc(ldata->qsee_handle, &dhandle, len) < 0) {
        ALOGE("DMABUF allocation failed");
        return -1;
    }

    memcpy(dhandle.map, buffer, len);

    if (send_modified_command_to_tz(ldata, dhandle) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    // Copy back result
    memcpy(buffer, dhandle.map, len);
    ldata->qsee_handle->dmabuf_free(&dhandle);

    return 0;
};

err_t fpc_set_auth_challenge(struct fpc_imp_data *data, int64_t challenge) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;

    fpc_send_auth_cmd_t auth_cmd = {
        .group_id = FPC_GROUP_FPCDATA,
        .cmd_id = FPC_SET_AUTH_CHALLENGE,
        .challenge = challenge,
    };

    if (send_custom_cmd(ldata, &auth_cmd, sizeof(auth_cmd)) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    ALOGD("Status :%d\n", auth_cmd.status);
    return auth_cmd.status;
}

int64_t fpc_load_auth_challenge(struct fpc_imp_data *data) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    fpc_load_auth_challenge_t cmd = {
        .group_id = FPC_GROUP_FPCDATA,
        .cmd_id = FPC_GET_AUTH_CHALLENGE,
    };

    if (send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    if (cmd.status != 0) {
        ALOGE("Bad status getting auth challenge: %d\n", cmd.status);
        return -2;
    }
    return cmd.challenge;
}

int64_t fpc_load_db_id(struct fpc_imp_data *data) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;

    // return cached auth_id value if available
    if (ldata->auth_id) {
        return ldata->auth_id;
    }
    fpc_get_db_id_cmd_t cmd = {
        .group_id = FPC_GROUP_NORMAL,
        .cmd_id = FPC_GET_TEMPLATE_ID,
    };

    if (send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending data to TZ\n");
        return -1;
    }
    // cache the auth_id value received from TZ
    ldata->auth_id = cmd.auth_id;
    return cmd.auth_id;
}

err_t fpc_get_hw_auth_obj(struct fpc_imp_data *data, void *buffer, uint32_t length) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    fpc_get_auth_result_t cmd = {
        .group_id = FPC_GROUP_FPCDATA,
        .cmd_id = FPC_GET_AUTH_RESULT,
        .length = AUTH_RESULT_LENGTH,
    };

    if (send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }
    if (length != AUTH_RESULT_LENGTH) {
        ALOGE("Weird inconsistency between auth length!???\n");
    }
    if (cmd.result != 0) {
        ALOGE("Get hw_auth_obj failed: %d\n", cmd.result);
        return cmd.result;
    }

    memcpy(buffer, cmd.auth_result, length);

    return 0;
}

err_t fpc_verify_auth_challenge(struct fpc_imp_data *data, void *hat, uint32_t size) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    int ret = send_buffer_command(ldata, FPC_GROUP_FPCDATA, FPC_AUTHORIZE_ENROL, hat, size);
    ALOGI("verify auth challenge: %d\n", ret);
    return ret;
}

err_t fpc_del_print_id(struct fpc_imp_data *data, uint32_t id) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;

    fpc_fingerprint_delete_t cmd = {
        .group_id = FPC_GROUP_NORMAL,
        .cmd_id = FPC_DELETE_FINGERPRINT,
        .fingerprint_id = id,
    };

    int ret = send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if (ret < 0) {
        ALOGE("Error sending command: %d\n", ret);
        return -1;
    }
    // remove the cached auth_id value upon deleting a fingerprint
    ldata->auth_id = 0;
    return cmd.status;
}

/**
 * Returns a positive value on success (finger is lost)
 * Returns 0 when an object is still touching the sensor
 * Returns a negative value on error
 */
err_t fpc_wait_finger_lost(struct fpc_imp_data *data) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    int result;

    result = send_normal_command(ldata, FPC_WAIT_FINGER_LOST);
    ALOGE_IF(result < 0, "Wait finger lost result: %d", result);
    return result;
}

/**
 * Returns a positive value on success (finger is down)
 * Returns 0 when an event occurs (and the operation has to be stopped)
 * Returns a negative value on error
 */
err_t fpc_wait_finger_down(struct fpc_imp_data *data) {
    ALOGV(__func__);
    int result = -1;
    fpc_data_t *ldata = (fpc_data_t *)data;

    result = send_normal_command(ldata, FPC_WAIT_FINGER_DOWN);
    ALOGE_IF(result, "Wait finger down result: %d", result);
    if (result)
        return result;

    result = fpc_poll_event(&data->event);

    if (result == FPC_EVENT_ERROR)
        return -1;
    return result == FPC_EVENT_FINGER;
}

// Attempt to capture image
err_t fpc_capture_image(struct fpc_imp_data *data) {
    ALOGV(__func__);

    fpc_data_t *ldata = (fpc_data_t *)data;

    int ret = fpc_wait_finger_lost(data);
    ALOGV("fpc_wait_finger_lost = 0x%08X", ret);
    if (ret < 0)
        return ret;
    if (ret) {
        ALOGV("Finger lost as expected");
        ret = fpc_wait_finger_down(data);
        ALOGV("fpc_wait_finger_down = 0x%08X", ret);
        if (ret < 0)
            return ret;
        if (ret) {
            ALOGD("Finger down, capturing image");
            ret = send_normal_command(ldata, FPC_CAPTURE_IMAGE);
            ALOGD("Image capture result: %d", ret);
        } else
            ret = 1001;
    } else {
        ret = 1000;

        // Extend the wakelock to prevent going to sleep before entering
        // a polling state again, which causes the sensor/hal to not
        // respond to any finger touches during deep sleep.
        fpc_keep_awake(&data->event, 1, 40);
        // Wait 20ms before checking if the finger is lost again.
        usleep(20000);
    }

    return ret;
}

bool fpc_navi_supported(struct fpc_imp_data __unused *data) {
    return false;
}

err_t fpc_navi_enter(struct fpc_imp_data __unused *data) {
    ALOGV(__func__);
    return -ENOSYS;
}

err_t fpc_navi_exit(struct fpc_imp_data __unused *data) {
    ALOGV(__func__);
    return -ENOSYS;
}

err_t fpc_navi_poll(struct fpc_imp_data __unused *data) {
    ALOGV(__func__);
    return -ENOSYS;
}

err_t fpc_enroll_step(struct fpc_imp_data *data, uint32_t *remaining_touches) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    fpc_enrol_step_t cmd = {
        .group_id = FPC_GROUP_NORMAL,
        .cmd_id = FPC_ENROL_STEP,
    };

    int ret = send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if (ret < 0) {
        ALOGE("Error sending command: %d\n", ret);
        return -1;
    }
    if (cmd.status < 0) {
        ALOGE("Error processing enroll step: %d\n", cmd.status);
        return -1;
    }
    *remaining_touches = cmd.remaining_touches;
    return cmd.status;
}

err_t fpc_enroll_start(struct fpc_imp_data *data, int __unused print_index) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    int ret = send_normal_command(ldata, FPC_BEGIN_ENROL);
    if (ret < 0) {
        ALOGE("Error beginning enrol: %d\n", ret);
        return -1;
    }
    return ret;
}

err_t fpc_enroll_end(struct fpc_imp_data *data, uint32_t *print_id) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    fpc_end_enrol_t cmd = {
        .group_id = FPC_GROUP_NORMAL,
        .cmd_id = FPC_END_ENROL,
    };

    if (send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending enrol command\n");
        return -1;
    }
    if (cmd.status != 0) {
        ALOGE("Error processing end enrol: %d\n", cmd.status);
        return -2;
    }

    *print_id = cmd.print_id;
    // remove the cached auth_id value upon enrolling a fingerprint
    ldata->auth_id = 0;
    return 0;
}

err_t fpc_auth_start(struct fpc_imp_data __unused *data) {
    ALOGV(__func__);
    return 0;
}

err_t fpc_auth_step(struct fpc_imp_data *data, uint32_t *print_id) {
    fpc_data_t *ldata = (fpc_data_t *)data;
    fpc_send_identify_t identify_cmd = {
        .commandgroup = FPC_GROUP_NORMAL,
        .command = FPC_IDENTIFY,
    };

    int result = send_custom_cmd(ldata, &identify_cmd, sizeof(identify_cmd));
    if (result) {
        ALOGE("Failed identifying, result=%d", result);
        return result;
    } else if (identify_cmd.status < 0) {
        ALOGE("Failed identifying, status=%d", identify_cmd.status);
        return identify_cmd.status;
    }

    ALOGD("Print identified as %u\n", identify_cmd.id);

    *print_id = identify_cmd.id;
    return identify_cmd.status;
}

err_t fpc_auth_end(struct fpc_imp_data __unused *data) {
    ALOGV(__func__);
    return 0;
}

err_t fpc_update_template(struct fpc_imp_data __unused *data) {
    // TODO: Implement for loire/tone
    return 1;
}

err_t fpc_get_print_index(struct fpc_imp_data *data, fpc_fingerprint_index_t *idx_data) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    fpc_fingerprint_list_t cmd = {
        .group_id = FPC_GROUP_NORMAL,
        .cmd_id = FPC_GET_FINGERPRINTS,
        .length = MAX_FINGERPRINTS,
    };
    unsigned int i;

    int ret = send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if (ret < 0 || cmd.status != 0) {
        ALOGE("Failed to retrieve fingerprints: rc = %d, status = %d", ret, cmd.status);
        return -EINVAL;
    } else if (cmd.length > MAX_FINGERPRINTS) {
        ALOGE("FPC_GET_FINGERPRINTS Returned more than MAX_FINGERPRINTS: %u", idx_data->print_count);
        return -EINVAL;
    }

    ALOGI("Found %d fingerprints", cmd.length);
    idx_data->print_count = cmd.length;
    for (i = 0; i < cmd.length; i++)
        idx_data->prints[i] = cmd.fingerprints[i];

    return 0;
}

err_t fpc_load_empty_db(struct fpc_imp_data *data) {
    err_t result;
    fpc_data_t *ldata = (fpc_data_t *)data;

    result = send_normal_command(ldata, FPC_LOAD_EMPTY_DB);
    if (result) {
        ALOGE("Error creating new empty database: %d\n", result);
        return result;
    }
    return 0;
}

err_t fpc_load_user_db(struct fpc_imp_data *data, char *path) {
    int result;
    fpc_data_t *ldata = (fpc_data_t *)data;

    ALOGD("Loading user db from %s\n", path);
    result = send_buffer_command(ldata, FPC_GROUP_DB, FPC_LOAD_DB, (const uint8_t *)path, (uint32_t)strlen(path) + 1);
    return result;
}

err_t fpc_set_gid(struct fpc_imp_data *data, uint32_t gid) {
    int result;
    fpc_data_t *ldata = (fpc_data_t *)data;
    fpc_set_gid_t cmd = {
        .group_id = FPC_GROUP_NORMAL,
        .cmd_id = FPC_SET_GID,
        .gid = gid,
    };

    ALOGD("Setting GID to %d\n", gid);
    result = send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if (!result)
        result = cmd.status;

    return result;
}

err_t fpc_store_user_db(struct fpc_imp_data *data, char *path) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)data;
    char temp_path[PATH_MAX];
    snprintf(temp_path, PATH_MAX - 1, "%s.tmp", path);
    int ret = send_buffer_command(ldata, FPC_GROUP_DB, FPC_STORE_DB, (const uint8_t *)temp_path, (uint32_t)strlen(temp_path) + 1);
    if (ret < 0) {
        ALOGE("storing database failed: %d\n", ret);
        return ret;
    }
    if (rename(temp_path, path) != 0) {
        ALOGE("Renaming temporary db from %s to %s failed: %d\n", temp_path, path, errno);
        return -2;
    }
    return ret;
}

err_t fpc_close(struct fpc_imp_data **data) {
    ALOGV(__func__);
    fpc_data_t *ldata = (fpc_data_t *)*data;

    ldata->qsee_handle->shutdown_app(&ldata->fpc_handle);
    if (fpc_set_power(&(*data)->event, FPC_PWROFF) < 0) {
        ALOGE("Error stopping device\n");
        return -1;
    }

    fpc_event_destroy(&ldata->data.event);
    fpc_uinput_destroy(&ldata->data.uinput);

    qsee_free_handle(&ldata->qsee_handle);
    free(ldata);
    *data = NULL;
    return 1;
}

err_t fpc_init(struct fpc_imp_data **data, int event_fd) {
    int ret = 0;

    struct QSEECom_handle *mFPC_handle = NULL;
    struct QSEECom_handle *mKeymasterHandle = NULL;
    struct qsee_handle *qsee_handle = NULL;

    ALOGI("INIT FPC TZ APP\n");
    if (qsee_open_handle(&qsee_handle) != 0) {
        ALOGE("Error loading QSEECom library");
        goto err;
    }

    fpc_data_t *fpc_data = (fpc_data_t *)malloc(sizeof(fpc_data_t));
    fpc_data->auth_id = 0;

    fpc_event_create(&fpc_data->data.event, event_fd);
    fpc_uinput_create(&fpc_data->data.uinput);

    if (fpc_set_power(&fpc_data->data.event, FPC_PWRON) < 0) {
        ALOGE("Error starting device\n");
        goto err_qsee;
    }

    ALOGI("Starting app %s\n", KM_TZAPP_NAME);
    if (qsee_handle->load_trustlet(qsee_handle, &mKeymasterHandle, KM_TZAPP_PATH, KM_TZAPP_NAME, 1024) < 0) {
        if (qsee_handle->load_trustlet(qsee_handle, &mKeymasterHandle, KM_TZAPP_PATH, KM_TZAPP_ALT_NAME, 1024) < 0) {
            ALOGE("Could not load app %s or %s\n", KM_TZAPP_NAME, KM_TZAPP_ALT_NAME);
            goto err_alloc;
        }
    }
    fpc_data->qsee_handle = qsee_handle;

    ALOGI("Starting app %s\n", FP_TZAPP_NAME);
    if (qsee_handle->load_trustlet(qsee_handle, &mFPC_handle, FP_TZAPP_PATH, FP_TZAPP_NAME, 128) < 0) {
        ALOGE("Could not load app : %s\n", FP_TZAPP_NAME);
        goto err_keymaster;
    }

    fpc_data->fpc_handle = mFPC_handle;

    if (fpc_data->qsee_handle->dmabuf_alloc(fpc_data->qsee_handle, &fpc_data->dhandle, 0x40) < 0) {
        ALOGE("DMABUF allocation failed");
        goto err_keymaster;
    }

    if ((ret = send_normal_command(fpc_data, FPC_INIT)) != 0) {
        ALOGE("Error sending FPC_INIT to tz: %d\n", ret);
        return -1;
    }

    // Start creating one off command to get cert from keymaster
    keymaster_cmd_t *req = (keymaster_cmd_t *)mKeymasterHandle->ion_sbuffer;
    req->cmd_id = 0x205;
    req->ret_val = 0x02;

    uint8_t *send_buf = mKeymasterHandle->ion_sbuffer;
    uint8_t *rec_buf = mKeymasterHandle->ion_sbuffer + 64;

    // Send command to keymaster
    if (qsee_handle->send_cmd(mKeymasterHandle, send_buf, 64, rec_buf, 1024 - 64) < 0) {
        goto err_keymaster;
    }

    keymaster_return_t *ret_data = (keymaster_return_t *)rec_buf;

    ALOGI("Keymaster Response Code : %u\n", ret_data->status);
    ALOGI("Keymaster Response Length : %u\n", ret_data->length);
    ALOGI("Keymaster Response Offset: %u\n", ret_data->offset);

    void *data_buff = &rec_buf[ret_data->offset];

    void *keydata = malloc(ret_data->length);
    int keylength = ret_data->length;
    memcpy(keydata, data_buff, keylength);

    qsee_handle->shutdown_app(&mKeymasterHandle);
    mKeymasterHandle = NULL;

    int result = send_buffer_command(fpc_data, FPC_GROUP_FPCDATA, FPC_SET_KEY_DATA, keydata, keylength);

    ALOGD("FPC_SET_KEY_DATA Result: %d\n", result);
    if (result != 0)
        return result;

    if (fpc_set_power(&fpc_data->data.event, FPC_PWROFF) < 0) {
        ALOGE("Error stopping device\n");
        goto err_alloc;
    }

    *data = (struct fpc_imp_data *)fpc_data;

    return 1;

err_keymaster:
    if (mKeymasterHandle != NULL)
        qsee_handle->shutdown_app(&mKeymasterHandle);
err_alloc:
    if (fpc_data != NULL) {
        fpc_data->qsee_handle->dmabuf_free(&fpc_data->dhandle);
        free(fpc_data);
    }
err_qsee:
    qsee_free_handle(&qsee_handle);
err:
    return -1;
}
