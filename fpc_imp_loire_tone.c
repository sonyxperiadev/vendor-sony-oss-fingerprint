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
#include "fpc_imp.h"

#include "tz_api_loire_tone.h"
#include "tz_api_tone.h"
#include "tz_api_loire.h"

#include "common.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#define LOG_TAG "FPC IMP"
#define LOG_NDEBUG 0

#include <cutils/log.h>
#include <limits.h>

#define SPI_CLK_FILE  "/sys/bus/spi/devices/spi0.1/clk_enable"
#define SPI_PREP_FILE SYSFS_PREFIX "/spi_prepare"
#define SPI_WAKE_FILE SYSFS_PREFIX "/wakeup_enable"
#define SPI_IRQ_FILE  SYSFS_PREFIX "/irq"

typedef struct {
    struct fpc_imp_data_t data;
    struct tz_command_list_t commands;
    struct QSEECom_handle *fpc_handle;
    struct qsee_handle_t* qsee_handle;
    uint32_t auth_id;
} fpc_data_t;

static err_t loire_poll_irq(char *path)
{
    err_t ret = 0;
    sysfs_write(SPI_WAKE_FILE, "disable");
    sysfs_write(SPI_WAKE_FILE, "enable");

    ret = sys_fs_irq_poll(path);

    sysfs_write(SPI_WAKE_FILE, "disable");
    return ret;
}


err_t loire_device_enable()
{
    if (sysfs_write(SPI_PREP_FILE,"enable")< 0) {
        return -1;
    }

/*    if (sysfs_write(SPI_CLK_FILE,"1")< 0) {
        return -1;
    }*/
    return 1;
}

err_t loire_device_disable()
{
/*    if (sysfs_write(SPI_CLK_FILE,"0")< 0) {
        return -1;
    }*/

    if (sysfs_write(SPI_PREP_FILE,"disable")< 0) {
        return -1;
    }
    return 1;
}

static const char *loire_fpc_error_str(int err)
{
    int realerror = err + 10;

    switch(realerror)
    {
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


err_t loire_send_modified_command_to_tz(fpc_data_t *ldata, struct qcom_km_ion_info_t ihandle)
{
    struct QSEECom_handle *handle = ldata->fpc_handle;

    fpc_send_mod_cmd_t* send_cmd = (fpc_send_mod_cmd_t*) handle->ion_sbuffer;
    void *rec_cmd = handle->ion_sbuffer + ldata->commands.tz_response_offset;
    struct QSEECom_ion_fd_info  ion_fd_info;

    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));

    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = 4;

    send_cmd->v_addr = (intptr_t) ihandle.ion_sbuffer;
    uint32_t length = (ihandle.sbuf_len + 4095) & (~4095);
    send_cmd->length = length;
    int result = ldata->qsee_handle->send_modified_cmd(handle,send_cmd,64,rec_cmd,64,&ion_fd_info);

    if(result)
    {
        ALOGE("Error sending modified command: %d\n", result);
        return -1;
    }
    if((result = *(int32_t*)rec_cmd) != 0)
    {
        ALOGE("Error in tz command (%d) : %s\n", result, loire_fpc_error_str(result));
        return -2;
    }


    return result;
}

err_t loire_send_normal_command(fpc_data_t *ldata, int command)
{
    struct qcom_km_ion_info_t ihandle;


    ihandle.ion_fd = 0;

    if (ldata->qsee_handle->ion_alloc(&ihandle, 0x40) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }

    // TODO: use single shared buffer instead of allocating/free'ing again and again
    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) ihandle.ion_sbuffer;

    send_cmd->group_id = 0x1;
    send_cmd->cmd_id = command;
    send_cmd->ret_val = 0x0;

    int ret = loire_send_modified_command_to_tz(ldata, ihandle);

    if(!ret) {
        ret = send_cmd->ret_val;
    }

    ldata->qsee_handle->ion_free(&ihandle);
    return ret;
}

err_t loire_send_buffer_command(fpc_data_t *ldata, uint32_t group_id, uint32_t cmd_id, const uint8_t *buffer, uint32_t length)
{
    struct qcom_km_ion_info_t ihandle;
    if (ldata->qsee_handle->ion_alloc(&ihandle, length + sizeof(fpc_send_buffer_t)) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }
    fpc_send_buffer_t *cmd_data = (fpc_send_buffer_t*)ihandle.ion_sbuffer;
    memset(ihandle.ion_sbuffer, 0, length + sizeof(fpc_send_buffer_t));
    cmd_data->group_id = group_id;
    cmd_data->cmd_id = cmd_id;
    cmd_data->length = length;
    memcpy(&cmd_data->data, buffer, length);

    if(loire_send_modified_command_to_tz(ldata, ihandle) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    int result = cmd_data->status;
    ldata->qsee_handle->ion_free(&ihandle);
    return result;
}


err_t loire_send_command_result_buffer(fpc_data_t *ldata, uint32_t group_id, uint32_t cmd_id, uint8_t *buffer, uint32_t length)
{
    struct qcom_km_ion_info_t ihandle;
    if (ldata->qsee_handle->ion_alloc(&ihandle, length + sizeof(fpc_send_buffer_t)) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }
    fpc_send_buffer_t *keydata_cmd = (fpc_send_buffer_t*)ihandle.ion_sbuffer;
    memset(ihandle.ion_sbuffer, 0, length + sizeof(fpc_send_buffer_t));
    keydata_cmd->group_id = group_id;
    keydata_cmd->cmd_id = cmd_id;
    keydata_cmd->length = length;

    if(loire_send_modified_command_to_tz(ldata, ihandle) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }
    memcpy(buffer, &keydata_cmd->data[0], length);

    int result = keydata_cmd->status;
    ldata->qsee_handle->ion_free(&ihandle);
    return result;
}

err_t loire_send_custom_cmd(fpc_data_t *ldata, void *buffer, uint32_t len)
{
    ALOGD(__func__);
    struct qcom_km_ion_info_t ihandle;

    if (ldata->qsee_handle->ion_alloc(&ihandle, len) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }

    memcpy(ihandle.ion_sbuffer, buffer, len);

    if(loire_send_modified_command_to_tz(ldata, ihandle) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    // Copy back result
    memcpy(buffer, ihandle.ion_sbuffer, len);
    ldata->qsee_handle->ion_free(&ihandle);

    return 0;
};


err_t loire_fpc_set_auth_challenge(fpc_imp_data_t *data, int64_t challenge)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;

    fpc_send_auth_cmd_t auth_cmd = {0};
    auth_cmd.group_id = ldata->commands.fpc_set_auth_challenge.group_id;
    auth_cmd.cmd_id = ldata->commands.fpc_set_auth_challenge.cmd_id;
    auth_cmd.challenge = challenge;

    if(loire_send_custom_cmd(ldata, &auth_cmd, sizeof(auth_cmd)) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    ALOGD("Status :%d\n", auth_cmd.status);
    return auth_cmd.status;
}

int64_t loire_fpc_load_auth_challenge(fpc_imp_data_t *data)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    fpc_load_auth_challenge_t cmd = {0};
    cmd.group_id = ldata->commands.fpc_get_auth_challenge.group_id;
    cmd.cmd_id = ldata->commands.fpc_get_auth_challenge.cmd_id;

    if(loire_send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }

    if(cmd.status != 0) {
        ALOGE("Bad status getting auth challenge: %d\n", cmd.status);
        return -2;
    }
    return cmd.challenge;
}

int64_t loire_fpc_load_db_id(fpc_imp_data_t *data)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;

    fpc_get_db_id_cmd_t cmd = {0};
    cmd.group_id = ldata->commands.fpc_set_auth_challenge.group_id;
    cmd.cmd_id = ldata->commands.fpc_set_auth_challenge.cmd_id;

    if(loire_send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending data to TZ\n");
        return -1;
    }
    return cmd.auth_id;
}

err_t loire_fpc_get_hw_auth_obj(fpc_imp_data_t *data, void * buffer, uint32_t length)
{
    ALOGD(__func__);
    fpc_get_auth_result_t cmd = {0};
    fpc_data_t *ldata = (fpc_data_t*)data;

    cmd.group_id = ldata->commands.fpc_get_auth_result.group_id;
    cmd.cmd_id = ldata->commands.fpc_get_auth_result.cmd_id;
    cmd.length = AUTH_RESULT_LENGTH;
    if(loire_send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending data to tz\n");
        return -1;
    }
    if(length != AUTH_RESULT_LENGTH)
    {
        ALOGE("Weird inconsistency between auth length!???\n");
    }
    if(cmd.result != 0)
    {
        ALOGE("Get hw_auth_obj failed: %d\n", cmd.result);
        return cmd.result;
    }

    memcpy(buffer, cmd.auth_result, length);

  return 0;
}

err_t loire_fpc_verify_auth_challenge(fpc_imp_data_t *data, void* hat, uint32_t size)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    int ret = loire_send_buffer_command(ldata, ldata->commands.fpc_auth_enrol.group_id, ldata->commands.fpc_auth_enrol.cmd_id, hat, size);
    ALOGE("verify auth challenge: %d\n", ret);
    return ret;
}


err_t loire_fpc_del_print_id(fpc_imp_data_t *data, uint32_t id)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;

    fpc_fingerprint_delete_t cmd = {0};
    cmd.group_id = ldata->commands.fpc_delete_fingerprints.group_id;
    cmd.cmd_id = ldata->commands.fpc_delete_fingerprints.cmd_id;
    cmd.fingerprint_id = id;

    int ret = loire_send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if(ret < 0)
    {
        ALOGE("Error sending command: %d\n", ret);
        return -1;
    }
    return cmd.status;
}

err_t loire_fpc_wait_finger_lost(fpc_imp_data_t *data)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    int result;

    result = loire_send_normal_command(ldata, ldata->commands.fpc_wait_for_finger_lost.cmd_id);
    if(result > 0)
        return 0;

    return -1;
}

err_t loire_fpc_wait_finger_down(fpc_imp_data_t *data)
{
    ALOGD(__func__);
    int result=-1;
    int i;
    fpc_data_t *ldata = (fpc_data_t*)data;

//    while(1)
    {
        result = loire_send_normal_command(ldata, ldata->commands.fpc_wait_for_finger_down.cmd_id);
        ALOGE("Wait finger down result: %d\n", result);
        if(result)
            return result;

        if((result = loire_poll_irq(SPI_IRQ_FILE)) == -1) {
                ALOGE("Error waiting for irq: %d\n", result);
                return -1;
        }

        result = loire_send_normal_command(ldata, ldata->commands.fpc_get_finger_status.cmd_id);
        if(result < 0)
        {
            ALOGE("Get finger status failed: %d\n", result);
            return result;
        }
        ALOGD("Finger status: %d\n", result);
        if(result)
            return 0;
    }
    return -1;
}

// Attempt to capture image
err_t loire_fpc_capture_image(fpc_imp_data_t *data)
{
    ALOGD(__func__);

    fpc_data_t *ldata = (fpc_data_t*)data;

    if (loire_device_enable() < 0) {
        ALOGE("Error starting device\n");
        return -1;
    }

    int ret = loire_fpc_wait_finger_lost(data);
    if(!ret)
    {
        ALOGE("Finger lost as expected\n");
        ret = loire_fpc_wait_finger_down(data);
        if(!ret)
        {
            ALOGE("Finger down, capturing image\n");
            ret = loire_send_normal_command(ldata, ldata->commands.fpc_capture_image.cmd_id);
            ALOGE("Image capture result :%d\n", ret);
        } else
            ret = 1001;
    } else {
        ret = 1000;
    }

    if (loire_device_disable() < 0) {
        ALOGE("Error stopping device\n");
        return -1;
    }

    loire_send_normal_command(ldata, ldata->commands.fpc_init.cmd_id);
    return ret;
}

err_t loire_fpc_enroll_step(fpc_imp_data_t *data, uint32_t *remaining_touches)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    fpc_enrol_step_t cmd = {0};
    cmd.group_id = ldata->commands.fpc_enrol_step.group_id;
    cmd.cmd_id = ldata->commands.fpc_enrol_step.cmd_id;

    int ret = loire_send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if(ret <0)
    {
        ALOGE("Error sending command: %d\n", ret);
        return -1;
    }
    if(cmd.status < 0)
    {
        ALOGE("Error processing enroll step: %d\n", cmd.status);
        return -1;
    }
    *remaining_touches = cmd.remaining_touches;
    return cmd.status;
}

err_t loire_fpc_enroll_start(fpc_imp_data_t * data, int __unused print_index)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    int ret = loire_send_normal_command(ldata, ldata->commands.fpc_begin_enrol.cmd_id);
    if(ret < 0) {
        ALOGE("Error beginning enrol: %d\n", ret);
        return -1;
    }
    return ret;
}

err_t loire_fpc_enroll_end(fpc_imp_data_t *data, uint32_t *print_id)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    fpc_end_enrol_t cmd = {0};
    cmd.group_id = ldata->commands.fpc_end_enrol.group_id;
    cmd.cmd_id = ldata->commands.fpc_end_enrol.cmd_id;

    if(loire_send_custom_cmd(ldata, &cmd, sizeof(cmd)) < 0) {
        ALOGE("Error sending enrol command\n");
        return -1;
    }
    if(cmd.status != 0) {
        ALOGE("Error processing end enrol: %d\n", cmd.status);
        return -2;
    }

    *print_id = cmd.print_id;
    return 0;
}


err_t loire_fpc_auth_start(fpc_imp_data_t __unused  *data)
{
    ALOGD(__func__);
    return 0;
}

err_t loire_fpc_auth_step(fpc_imp_data_t *data, uint32_t *print_id)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    fpc_send_identify_t identify_cmd = {0};
    identify_cmd.commandgroup = ldata->commands.fpc_identify.group_id;
    identify_cmd.command = ldata->commands.fpc_identify.cmd_id;
    int result = loire_send_custom_cmd(ldata, &identify_cmd, sizeof(identify_cmd));
    if(result)
    {
        ALOGE("Error identifying: %d || %d\n", result, identify_cmd.status);
        return -1;
    }


    ALOGD("Print identified as %d\n", identify_cmd.id);

    *print_id = identify_cmd.id;
    return identify_cmd.status;
}

err_t loire_fpc_auth_end(fpc_imp_data_t __unused *data)
{
    ALOGD(__func__);
    return 0;
}


err_t loire_fpc_get_print_count(fpc_imp_data_t __unused *data)
{
    ALOGD(__func__);
    return 0;
}


fpc_fingerprint_index_t loire_fpc_get_print_index(fpc_imp_data_t *data, uint32_t __unused count)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    fpc_fingerprint_index_t idx_data = {0};
    fpc_fingerprint_list_t cmd = {0};
    unsigned int i;

    cmd.group_id = ldata->commands.fpc_get_fingerprints.group_id;
    cmd.cmd_id = ldata->commands.fpc_get_fingerprints.cmd_id;

    int ret = loire_send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if(ret < 0 || cmd.status != 0)
    {
        ALOGE("Error retrieving fingerprints\n");
    }

    ALOGE("Found %d fingerprints\n", cmd.length);
    for(i=0; i<cmd.length; i++)
    {
        idx_data.prints[i] = cmd.fingerprints[i];
    }

    return idx_data;
}


err_t loire_fpc_get_user_db_length(fpc_imp_data_t __unused *data)
{
    ALOGD(__func__);
    return 0;
}

err_t loire_fpc_load_empty_db(fpc_imp_data_t *data) {
    err_t result;
    fpc_data_t *ldata = (fpc_data_t*)data;

    result = loire_send_normal_command(ldata, ldata->commands.fpc_load_empty_db.cmd_id);
    if(result)
    {
        ALOGE("Error creating new empty database: %d\n", result);
        return result;
    }
    return 0;
}


err_t loire_fpc_load_user_db(fpc_imp_data_t *data, char* path)
{
    int result;
    struct stat sb;
    fpc_data_t *ldata = (fpc_data_t*)data;

    ALOGD("Loading user db from %s\n", path);
    result = loire_send_buffer_command(ldata, ldata->commands.fpc_load_db.group_id, ldata->commands.fpc_load_db.cmd_id, (const uint8_t*)path, (uint32_t)strlen(path)+1);
    return result;
}

err_t loire_fpc_set_gid(fpc_imp_data_t *data, uint32_t gid)
{
    int result;
    fpc_data_t *ldata = (fpc_data_t*)data;
    fpc_set_gid_t cmd = {0};
    cmd.group_id = ldata->commands.fpc_set_gid.group_id;
    cmd.cmd_id = ldata->commands.fpc_set_gid.cmd_id;
    cmd.gid = gid;

    ALOGD("Setting GID to %d\n", gid);
    result = loire_send_custom_cmd(ldata, &cmd, sizeof(cmd));
    if(!result)
        result = cmd.status;

    return result;
}

err_t loire_fpc_store_user_db(fpc_imp_data_t *data, uint32_t __unused length, char* path)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    char temp_path[PATH_MAX];
    snprintf(temp_path, PATH_MAX - 1, "%s.tmp", path);
    int ret = loire_send_buffer_command(ldata, ldata->commands.fpc_store_db.group_id, ldata->commands.fpc_store_db.cmd_id, (const uint8_t*)temp_path, (uint32_t)strlen(temp_path)+1);
    if(ret < 0)
    {
        ALOGE("storing database failed: %d\n", ret);
        return ret;
    }
    if(rename(temp_path, path) != 0)
    {
        ALOGE("Renaming temporary db from %s to %s failed: %d\n", temp_path, path, errno);
        return -2;
    }
    return ret;
}

err_t loire_fpc_close(fpc_imp_data_t **data)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;
    ldata->qsee_handle->shutdown_app(&ldata->fpc_handle);
    if (loire_device_disable() < 0) {
        ALOGE("Error stopping device\n");
        return -1;
    }
    qsee_free_handle(&ldata->qsee_handle);
    free(ldata);
    *data = NULL;
    return 1;
}

err_t loire_fpc_init(fpc_imp_data_t **data)
{
    int ret=0;

    struct QSEECom_handle * mFPC_handle = NULL;
    struct QSEECom_handle * mKeymasterHandle = NULL;
    struct qsee_handle_t* qsee_handle = NULL;

    ALOGE("INIT FPC TZ APP\n");
    if(qsee_open_handle(&qsee_handle) != 0) {
        ALOGE("Error loading QSEECom library");
        goto err;
    }

    if (loire_device_enable() < 0) {
        ALOGE("Error starting device\n");
        goto err_qsee;
    }

    fpc_data_t *fpc_data = (fpc_data_t*)malloc(sizeof(fpc_data_t));
    fpc_data->auth_id = 0;
    fpc_data->commands = loire_commands;

    ALOGE("Starting app %s\n", KM_TZAPP_NAME);
    if (qsee_handle->load_trustlet(qsee_handle, &mKeymasterHandle, KM_TZAPP_PATH, KM_TZAPP_NAME, 1024) < 0) {
        if (qsee_handle->load_trustlet(qsee_handle, &mKeymasterHandle, KM_TZAPP_PATH, KM_TZAPP_ALT_NAME, 1024) < 0) {
            ALOGE("Could not load app %s or %s\n", KM_TZAPP_NAME, KM_TZAPP_ALT_NAME);
            goto err_alloc;
        }
    }
    fpc_data->qsee_handle = qsee_handle;


    ALOGE("Starting app %s\n", FP_TZAPP_NAME);
    if (qsee_handle->load_trustlet(qsee_handle, &mFPC_handle, FP_TZAPP_PATH, FP_TZAPP_NAME, 128) < 0) {
        ALOGE("Could not load app : %s\n", FP_TZAPP_NAME);
        goto err_keymaster;
    }

    fpc_data->fpc_handle = mFPC_handle;

    if ((ret = loire_send_normal_command(fpc_data, fpc_data->commands.fpc_init.cmd_id)) != 0) {
        ALOGE("Error sending FPC_INIT to tz: %d\n", ret);
        return -1;
    }

    // Start creating one off command to get cert from keymaster
    keymaster_cmd_t *req = (keymaster_cmd_t *) mKeymasterHandle->ion_sbuffer;
    req->cmd_id = 0x205;
    req->ret_val = 0x02;

    uint8_t * send_buf = mKeymasterHandle->ion_sbuffer;
    uint8_t * rec_buf = mKeymasterHandle->ion_sbuffer + 64;

    //Send command to keymaster
    if (qsee_handle->send_cmd(mKeymasterHandle, send_buf, 64, rec_buf, 1024-64) < 0) {
        goto err_keymaster;
    }

    keymaster_return_t* ret_data = (keymaster_return_t*) rec_buf;

    ALOGE("Keymaster Response Code : %u\n", ret_data->status);
    ALOGE("Keymaster Response Length : %u\n", ret_data->length);
    ALOGE("Keymaster Response Offset: %u\n", ret_data->offset);

    void * data_buff = &rec_buf[ret_data->offset];

    void *keydata = malloc(ret_data->length);
    int keylength = ret_data->length;
    memcpy(keydata, data_buff, keylength);

    qsee_handle->shutdown_app(&mKeymasterHandle);
    mKeymasterHandle = NULL;

    int result = loire_send_buffer_command(fpc_data, fpc_data->commands.fpc_set_key_data.group_id, fpc_data->commands.fpc_set_key_data.cmd_id, keydata, keylength);

    ALOGD("FPC_SET_KEY_DATA Result: %d\n", result);
    if(result != 0)
        return result;

    if (loire_device_disable() < 0) {
        ALOGE("Error stopping device\n");
        goto err_alloc;
    }

    *data = (fpc_imp_data_t*)fpc_data;

    return 1;

err_keymaster:
    if(mKeymasterHandle != NULL)
        qsee_handle->shutdown_app(&mKeymasterHandle);
err_alloc:
    if(fpc_data != NULL)
        free(fpc_data);
err_qsee:
    qsee_free_handle(&qsee_handle);
err:
    return -1;
}


err_t tone_fpc_init(fpc_imp_data_t **data)
{
    int ret=0;

    struct QSEECom_handle * mFPC_handle = NULL;
    struct QSEECom_handle * mKeymasterHandle = NULL;
    struct qsee_handle_t* qsee_handle = NULL;

    ALOGE("INIT FPC TZ APP\n");
    if(qsee_open_handle(&qsee_handle) != 0) {
        ALOGE("Error loading QSEECom library");
        goto err;
    }

    if (loire_device_enable() < 0) {
        ALOGE("Error starting device\n");
        goto err_qsee;
    }

    fpc_data_t *fpc_data = (fpc_data_t*)malloc(sizeof(fpc_data_t));
    fpc_data->auth_id = 0;
    fpc_data->commands = tone_commands;

    ALOGE("Starting app %s\n", KM_TZAPP_NAME);
    if (qsee_handle->load_trustlet(qsee_handle, &mKeymasterHandle, KM_TZAPP_PATH, KM_TZAPP_NAME, 1024) < 0) {
        if (qsee_handle->load_trustlet(qsee_handle, &mKeymasterHandle, KM_TZAPP_PATH, KM_TZAPP_ALT_NAME, 1024) < 0) {
            ALOGE("Could not load app %s or %s\n", KM_TZAPP_NAME, KM_TZAPP_ALT_NAME);
            goto err_alloc;
        }
    }
    fpc_data->qsee_handle = qsee_handle;


    ALOGE("Starting app %s\n", FP_TZAPP_NAME);
    if (qsee_handle->load_trustlet(qsee_handle, &mFPC_handle, FP_TZAPP_PATH, FP_TZAPP_NAME, 128) < 0) {
        ALOGE("Could not load app : %s\n", FP_TZAPP_NAME);
        goto err_keymaster;
    }

    fpc_data->fpc_handle = mFPC_handle;

    if ((ret = loire_send_normal_command(fpc_data, fpc_data->commands.fpc_init.cmd_id)) != 0) {
        ALOGE("Error sending FPC_INIT to tz: %d\n", ret);
        return -1;
    }

    // Start creating one off command to get cert from keymaster
    keymaster_cmd_t *req = (keymaster_cmd_t *) mKeymasterHandle->ion_sbuffer;
    req->cmd_id = 0x205;
    req->ret_val = 0x02;

    uint8_t * send_buf = mKeymasterHandle->ion_sbuffer;
    uint8_t * rec_buf = mKeymasterHandle->ion_sbuffer + 64;

    //Send command to keymaster
    if (qsee_handle->send_cmd(mKeymasterHandle, send_buf, 64, rec_buf, 1024-64) < 0) {
        goto err_keymaster;
    }

    keymaster_return_t* ret_data = (keymaster_return_t*) rec_buf;

    ALOGE("Keymaster Response Code : %u\n", ret_data->status);
    ALOGE("Keymaster Response Length : %u\n", ret_data->length);
    ALOGE("Keymaster Response Offset: %u\n", ret_data->offset);

    void * data_buff = &rec_buf[ret_data->offset];

    void *keydata = malloc(ret_data->length);
    int keylength = ret_data->length;
    memcpy(keydata, data_buff, keylength);

    qsee_handle->shutdown_app(&mKeymasterHandle);
    mKeymasterHandle = NULL;

    int result = loire_send_buffer_command(fpc_data, fpc_data->commands.fpc_set_key_data.group_id, fpc_data->commands.fpc_set_key_data.cmd_id, keydata, keylength);

    ALOGD("FPC_SET_KEY_DATA Result: %d\n", result);
    if(result != 0)
        return result;

    if (loire_device_disable() < 0) {
        ALOGE("Error stopping device\n");
        goto err_alloc;
    }

    *data = (fpc_imp_data_t*)fpc_data;

    return 1;

err_keymaster:
    if(mKeymasterHandle != NULL)
        qsee_handle->shutdown_app(&mKeymasterHandle);
err_alloc:
    if(fpc_data != NULL)
        free(fpc_data);
err_qsee:
    qsee_free_handle(&qsee_handle);
err:
    return -1;
}

char* loire_fpc_get_name(fpc_imp_data_t *data) {
    fpc_data_t *ldata = (fpc_data_t*)data;
    return ldata->commands.tz_imp_name;
}

static struct fpc_imp_func_t loire_imp_functions = {
    .fpc_get_name = loire_fpc_get_name,
    .fpc_load_db_id = loire_fpc_load_db_id,
    .fpc_load_auth_challenge = loire_fpc_load_auth_challenge,
    .fpc_set_auth_challenge = loire_fpc_set_auth_challenge,
    .fpc_verify_auth_challenge = loire_fpc_verify_auth_challenge,
    .fpc_get_hw_auth_obj = loire_fpc_get_hw_auth_obj,
    .fpc_get_print_count = loire_fpc_get_print_count,
    .fpc_del_print_id = loire_fpc_del_print_id,
    .fpc_get_print_index = loire_fpc_get_print_index,
    .fpc_capture_image = loire_fpc_capture_image,
    .fpc_enroll_step = loire_fpc_enroll_step,
    .fpc_enroll_start = loire_fpc_enroll_start,
    .fpc_enroll_end = loire_fpc_enroll_end,
    .fpc_auth_start = loire_fpc_auth_start,
    .fpc_auth_step = loire_fpc_auth_step,
    .fpc_auth_end = loire_fpc_auth_end,
    .fpc_get_user_db_length = loire_fpc_get_user_db_length,
    .fpc_set_gid = loire_fpc_set_gid,
    .fpc_load_user_db = loire_fpc_load_user_db,
    .fpc_load_empty_db = loire_fpc_load_empty_db,
    .fpc_store_user_db = loire_fpc_store_user_db,
    .fpc_close = loire_fpc_close,
    .fpc_init = loire_fpc_init,
    .per_db_gid = false,
};

void fpc_loire_init_func(fpc_imp_func_t **func){

    //Can alloc dinamically as well if needed
    //fpc_imp_func_t *functions = malloc(sizeof(fpc_imp_func_t));
    //functions->get_name = fpc_loire_get_imp_name;

    *func = &loire_imp_functions;
}


static struct fpc_imp_func_t tone_imp_functions = {
    .fpc_get_name = loire_fpc_get_name,
    .fpc_load_db_id = loire_fpc_load_db_id,
    .fpc_load_auth_challenge = loire_fpc_load_auth_challenge,
    .fpc_set_auth_challenge = loire_fpc_set_auth_challenge,
    .fpc_verify_auth_challenge = loire_fpc_verify_auth_challenge,
    .fpc_get_hw_auth_obj = loire_fpc_get_hw_auth_obj,
    .fpc_get_print_count = loire_fpc_get_print_count,
    .fpc_del_print_id = loire_fpc_del_print_id,
    .fpc_get_print_index = loire_fpc_get_print_index,
    .fpc_capture_image = loire_fpc_capture_image,
    .fpc_enroll_step = loire_fpc_enroll_step,
    .fpc_enroll_start = loire_fpc_enroll_start,
    .fpc_enroll_end = loire_fpc_enroll_end,
    .fpc_auth_start = loire_fpc_auth_start,
    .fpc_auth_step = loire_fpc_auth_step,
    .fpc_auth_end = loire_fpc_auth_end,
    .fpc_get_user_db_length = loire_fpc_get_user_db_length,
    .fpc_set_gid = loire_fpc_set_gid,
    .fpc_load_user_db = loire_fpc_load_user_db,
    .fpc_load_empty_db = loire_fpc_load_empty_db,
    .fpc_store_user_db = loire_fpc_store_user_db,
    .fpc_close = loire_fpc_close,
    .fpc_init = tone_fpc_init,
    .per_db_gid = false,
};

void fpc_tone_init_func(fpc_imp_func_t **func){

    //Can alloc dinamically as well if needed
    //fpc_imp_func_t *functions = malloc(sizeof(fpc_imp_func_t));
    //functions->get_name = fpc_loire_get_imp_name;

    *func = &tone_imp_functions;
}
