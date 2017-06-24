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
#include "tz_api_kitakami.h"
#include <string.h>
#include "common.h"

#define LOG_TAG "FPC IMP"
#define LOG_NDEBUG 0

#include <cutils/log.h>
#include <stdlib.h>
#include <sys/stat.h>


#define SPI_CLK_FILE "/sys/bus/spi/devices/spi0.1/clk_enable"
#define SPI_PREP_FILE "/sys/bus/spi/devices/spi0.1/spi_prepare"
#define SPI_WAKE_FILE "/sys/bus/spi/devices/spi0.1/wakeup_enable"
#define SPI_IRQ_FILE "/sys/bus/spi/devices/spi0.1/irq"


typedef struct {
    struct fpc_imp_data_t data;
    struct QSEECom_handle *fpc_handle;
    struct qsee_handle_t* qsee_handle;
    //uint32_t auth_id;
} fpc_data_t;

err_t kitakami_device_enable()
{
    if (sysfs_write(SPI_PREP_FILE,"enable")< 0) {
        return -1;
    }

    if (sysfs_write(SPI_CLK_FILE,"1")< 0) {
        return -1;
    }
    return 1;
}

err_t kitakami_device_disable()
{
    if (sysfs_write(SPI_CLK_FILE,"0")< 0) {
        return -1;
    }

    if (sysfs_write(SPI_PREP_FILE,"disable")< 0) {
        return -1;
    }
    return 1;
}

err_t kitakami_send_modified_command_to_tz(fpc_data_t *ldata, uint32_t cmd, void * buffer, uint32_t len)
{

    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_mod_cmd_t* send_cmd = (fpc_send_mod_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    struct QSEECom_ion_fd_info  ion_fd_info;
    struct qcom_km_ion_info_t ihandle;

    ihandle.ion_fd = 0;

    if (qsee_handle->ion_alloc(&ihandle, len) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }

    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = 4;

    send_cmd->cmd_id = cmd;
    send_cmd->v_addr = (intptr_t) ihandle.ion_sbuffer;
    send_cmd->length = len;
    send_cmd->extra = 0x00;

    memcpy((unsigned char *)ihandle.ion_sbuffer, buffer, len);

    int ret = qsee_handle->send_modified_cmd(handle,send_cmd,64,rec_cmd,64,&ion_fd_info);

    if(ret < 0) {
        qsee_handle->ion_free(&ihandle);
        return -1;
    }

    if (send_cmd->v_addr != 0) {
        ALOGE("Error on TZ\n");
        qsee_handle->ion_free(&ihandle);
        return -1;
    }

    qsee_handle->ion_free(&ihandle);
    return 0;
}

err_t kitakami_send_normal_command(fpc_data_t *ldata, uint32_t cmd, uint32_t param)
{
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = cmd;
    send_cmd->ret_val = param;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }

    return rec_cmd->ret_val;
}

int64_t kitakami_get_int64_command(fpc_data_t *ldata, uint32_t cmd, uint32_t param)
{
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_int64_cmd_t* send_cmd = (fpc_send_int64_cmd_t*) handle->ion_sbuffer;
    fpc_send_int64_cmd_t* rec_cmd = (fpc_send_int64_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = cmd;
    send_cmd->ret_val = param;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }

    return send_cmd->ret_val;

}

err_t kitakami_fpc_set_auth_challenge(fpc_imp_data_t *data, int64_t challenge)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)data;

    return kitakami_send_normal_command(ldata, FPC_SET_AUTH_CHALLENGE,0);
}

int64_t kitakami_fpc_load_auth_challenge(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    return kitakami_get_int64_command(ldata, FPC_GET_AUTH_CHALLENGE,0);
}

int64_t kitakami_fpc_load_db_id(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    return kitakami_get_int64_command(ldata, FPC_GET_DB_ID,0);
}

err_t kitakami_fpc_get_hw_auth_obj(fpc_imp_data_t *data, void *buffer, uint32_t length)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_mod_cmd_t* send_cmd = (fpc_send_mod_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    struct QSEECom_ion_fd_info  ion_fd_info;
    struct qcom_km_ion_info_t ihandle;

    ihandle.ion_fd = 0;

    if (qsee_handle->ion_alloc(&ihandle, length) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }

    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = 4;

    send_cmd->cmd_id = FPC_GET_AUTH_HAT;
    send_cmd->v_addr = (intptr_t) ihandle.ion_sbuffer;
    send_cmd->length = length;
    send_cmd->extra = 0x00;

    memset((unsigned char *)ihandle.ion_sbuffer, 0, length);

    int ret = qsee_handle->send_modified_cmd(handle, send_cmd, 64, rec_cmd, 64, &ion_fd_info);

    memcpy(buffer, (unsigned char *)ihandle.ion_sbuffer, length);

    if(ret < 0) {
        qsee_handle->ion_free(&ihandle);
        return -1;
    }

    if (send_cmd->v_addr != 0) {
        ALOGE("Error on TZ\n");
        qsee_handle->ion_free(&ihandle);
        return -1;
    }

    qsee_handle->ion_free(&ihandle);
    return 0;

}

err_t kitakami_fpc_verify_auth_challenge(fpc_imp_data_t *data, void* hat, uint32_t size)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    return kitakami_send_modified_command_to_tz(ldata, FPC_VERIFY_AUTH_CHALLENGE,hat,size);
}

static err_t kitakami_fpc_get_remaining_touches(fpc_data_t *ldata)
{
    return kitakami_send_normal_command(ldata, FPC_GET_REMAINING_TOUCHES,0);
}

err_t kitakami_fpc_get_print_count(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_GET_ID_COUNT;
    send_cmd->ret_val = 0x00;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }

    return send_cmd->ret_val;
}

fpc_fingerprint_index_t kitakami_fpc_get_print_ids(fpc_imp_data_t *data, uint32_t count)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_fingerprint_index_t idx_data;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_get_pint_index_cmd_t* rec_cmd = (fpc_get_pint_index_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_GET_ID_LIST;
    send_cmd->ret_val = count;
    send_cmd->length = count;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    idx_data.prints[0] = rec_cmd->p1;
    idx_data.prints[1] = rec_cmd->p2;
    idx_data.prints[2] = rec_cmd->p3;
    idx_data.prints[3] = rec_cmd->p4;
    idx_data.prints[4] = rec_cmd->p5;
    idx_data.print_count = rec_cmd->print_count;

    return idx_data;
}


err_t kitakami_fpc_get_print_id(fpc_imp_data_t *data, int id)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_GET_PRINT_ID;
    send_cmd->ret_val = id;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }

    return send_cmd->ret_val;
}

err_t kitakami_fpc_del_print_id(fpc_imp_data_t *data, uint32_t id)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    uint32_t print_count = kitakami_fpc_get_print_count(data);
    ALOGD("%s : print count is : %u", __func__, print_count);
    fpc_fingerprint_index_t print_indexs = kitakami_fpc_get_print_ids(data, print_count);
    ALOGI("%s : delete print : %lu", __func__,(unsigned long) id);

    for (uint32_t i = 0; i < print_indexs.print_count; i++){

        uint32_t print_id = kitakami_fpc_get_print_id(data, print_indexs.prints[i]);

        if (print_id == id){
                ALOGD("%s : Print index found at : %d", __func__, i);
                return kitakami_send_normal_command(ldata, FPC_GET_DEL_PRINT,print_indexs.prints[i]);
        }
    }

    return -1;
}

// Returns -1 on error, 1 on check again and 0 on ready to capture
err_t kitakami_fpc_wait_for_finger(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    int finger_state  = kitakami_send_normal_command(ldata, FPC_CHK_FP_LOST,FPC_CHK_FP_LOST);

    if (finger_state == 4) {
        ALOGD("%s : WAIT FOR FINGER UP\n", __func__);
    } else if (finger_state == 8) {
        ALOGD("%s : WAIT FOR FINGER DOWN\n", __func__);
    } else if (finger_state == 2) {
        ALOGD("%s : WAIT FOR FINGER NOT NEEDED\n", __func__);
        return 1;
    } else {
        return -1;
    }

    sysfs_write(SPI_WAKE_FILE,"1");
    if (kitakami_send_normal_command(ldata, FPC_SET_WAKE,0) != 0) {
        ALOGE("Error sending FPC_SET_WAKE to tz\n");
        return -1;
    }
    sysfs_write(SPI_CLK_FILE,"0");

    ALOGD("Attempting to poll device IRQ\n");

    if (sys_fs_irq_poll(SPI_IRQ_FILE) < 0) {
        sysfs_write(SPI_CLK_FILE,"1");
        sysfs_write(SPI_WAKE_FILE,"0");
        return 1;
    }

    sysfs_write(SPI_CLK_FILE,"1");
    sysfs_write(SPI_WAKE_FILE,"0");

    int wake_type = kitakami_send_normal_command(ldata, FPC_GET_WAKE_TYPE,0);

    if (wake_type == 3) {
        ALOGD("%s : READY TO CAPTURE\n", __func__);
        return 0;
    } else {
        ALOGD("%s : NOT READY TRY AGAIN\n", __func__);
        return 1;
    }

    return 1;
}

// Attempt to capture image
err_t kitakami_fpc_capture_image(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;

    if (kitakami_device_enable() < 0) {
        ALOGE("Error starting device\n");
        return -1;
    }


    int ret = kitakami_fpc_wait_for_finger(data);

    if (ret == 0) {
        //If wait reported 0 we can try and capture the image
        ret = kitakami_send_normal_command(ldata, FPC_CAPTURE_IMAGE,0);
    } else {
        //return a high value as to not trigger a user notification
        ret = 1000; //same as FINGERPRINT_ERROR_VENDOR_BASE
    }

    if (kitakami_device_disable() < 0) {
        ALOGE("Error stopping device\n");
        return -1;
    }

    return ret;
}

err_t kitakami_fpc_enroll_step(fpc_imp_data_t *data, uint32_t *remaining_touches)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_ENROLL_STEP;
    send_cmd->ret_val = 0x24;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }
    if(rec_cmd->ret_val < 0)
        return rec_cmd->ret_val;

    int touches = kitakami_fpc_get_remaining_touches(ldata);
    if(touches < 0)
        return touches;

    *remaining_touches = (uint32_t)touches;
    return rec_cmd->ret_val;
}

err_t kitakami_fpc_enroll_start(fpc_imp_data_t *data, int print_index)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_enroll_start_cmd_t* send_cmd = (fpc_send_enroll_start_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_ENROLL_START;
    send_cmd->ret_val = 0x00;
    send_cmd->na1 = 0x45;
    send_cmd->print_index = print_index;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }

    return rec_cmd->ret_val;
}

err_t kitakami_fpc_enroll_end(fpc_imp_data_t *data, uint32_t *print_id)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    int index = kitakami_send_normal_command(ldata, FPC_ENROLL_END,0x0);

    if (index < 0 || index > 4) {
        ALOGE("Error sending FPC_ENROLL_END to tz\n");
        return -1;
    }

    *print_id = kitakami_fpc_get_print_id(data, index);

    return 0;
}

err_t kitakami_fpc_auth_start(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    uint32_t print_count = (uint32_t)kitakami_fpc_get_print_count(data);
    fpc_fingerprint_index_t prints;
    ALOGI("%s : Number Of Prints Available : %d",__func__,print_count);

    prints = kitakami_fpc_get_print_ids(data, print_count);

    fpc_get_pint_index_cmd_t* send_cmd = (fpc_get_pint_index_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;


    send_cmd->cmd_id = FPC_AUTH_START;
    send_cmd->p1 = prints.prints[0];
    send_cmd->p2 = prints.prints[1];
    send_cmd->p3 = prints.prints[2];
    send_cmd->p4 = prints.prints[3];
    send_cmd->p5 = prints.prints[4];
    send_cmd->print_count = prints.print_count;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        ALOGE("Error sending FPC_AUTH_START to tz\n");
        return -1;
    }

    return rec_cmd->ret_val;
}

err_t kitakami_fpc_auth_step(fpc_imp_data_t *data, uint32_t *print_id)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_send_auth_cmd_t* rec_cmd = (fpc_send_auth_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_AUTH_STEP;
    send_cmd->ret_val = 0x00;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }

    //if the print didnt capture properly return error and continue
    if (rec_cmd->ret_val < 2) {
        return -1;
    }



    *print_id = (uint32_t)kitakami_fpc_get_print_id(data, rec_cmd->id);
    return 0;
}

err_t kitakami_fpc_auth_end(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    err_t ret = kitakami_send_normal_command(ldata, FPC_AUTH_END,0x0);

    if (ret != 0) {
        ALOGE("Error sending FPC_AUTH_END to tz\n");
        return -1;
    }
    return ret;
}

fpc_fingerprint_index_t kitakami_fpc_get_print_index(fpc_imp_data_t *data, uint32_t count)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;
    fpc_fingerprint_index_t idx_data;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_get_pint_index_cmd_t* rec_cmd = (fpc_get_pint_index_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_GET_ID_LIST;
    send_cmd->ret_val = count;
    send_cmd->length = count;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    idx_data.prints[0] = (uint32_t)kitakami_fpc_get_print_id(data, rec_cmd->p1);
    idx_data.prints[1] = (uint32_t)kitakami_fpc_get_print_id(data, rec_cmd->p2);
    idx_data.prints[2] = (uint32_t)kitakami_fpc_get_print_id(data, rec_cmd->p3);
    idx_data.prints[3] = (uint32_t)kitakami_fpc_get_print_id(data, rec_cmd->p4);
    idx_data.prints[4] = (uint32_t)kitakami_fpc_get_print_id(data, rec_cmd->p5);
    idx_data.print_count = rec_cmd->print_count;

    return idx_data;
}


err_t kitakami_fpc_get_user_db_length(fpc_imp_data_t *data)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_std_cmd_t* send_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    send_cmd->cmd_id = FPC_GET_DB_LENGTH;
    send_cmd->ret_val = 0x00;

    int ret = qsee_handle->send_cmd(handle,send_cmd,64,rec_cmd,64);

    if(ret < 0) {
        return -1;
    }

    return send_cmd->ret_val;
}


err_t kitakami_fpc_load_user_db(fpc_imp_data_t *data, char* path)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;
    struct stat sb;

    ALOGD(__func__);

    if(stat(path, &sb) == -1) {
        // TODO: Should we load a new DB and store it here?
        return 0;
    }

    FILE *f = fopen(path, "r");

    if (f == NULL) {
        ALOGE("Error opening file : %s", path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    ALOGI("Loading DB of size : %ld", fsize);

    struct qcom_km_ion_info_t ihandle;
    struct QSEECom_ion_fd_info  ion_fd_info;

    if (qsee_handle->ion_alloc(&ihandle, fsize) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }

    fread(ihandle.ion_sbuffer, fsize, 1, f);

    fclose(f);

    fpc_send_mod_cmd_t* send_cmd = (fpc_send_mod_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = 4;

    send_cmd->cmd_id = FPC_SET_DB_DATA;
    send_cmd->v_addr = (intptr_t) ihandle.ion_sbuffer;
    send_cmd->length = fsize;
    send_cmd->extra = 0x00;

    int ret = qsee_handle->send_modified_cmd(handle,send_cmd,64,rec_cmd,64,&ion_fd_info);

    if(ret < 0) {
        qsee_handle->ion_free(&ihandle);
        return -1;
    }

    if (send_cmd->v_addr != 0) {
        ALOGE("Error on TZ\n");
        qsee_handle->ion_free(&ihandle);
        return -1;
    }

    qsee_handle->ion_free(&ihandle);
    return 0;

}

err_t kitakami_fpc_store_user_db(fpc_imp_data_t *data, uint32_t length, char* path)
{
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    fpc_send_mod_cmd_t* send_cmd = (fpc_send_mod_cmd_t*) handle->ion_sbuffer;
    fpc_send_std_cmd_t* rec_cmd = (fpc_send_std_cmd_t*) handle->ion_sbuffer + 64;

    struct QSEECom_ion_fd_info  ion_fd_info;
    struct qcom_km_ion_info_t ihandle;

    ihandle.ion_fd = 0;

    if (qsee_handle->ion_alloc(&ihandle, length) <0) {
        ALOGE("ION allocation  failed");
        return -1;
    }

    memset(&ion_fd_info, 0, sizeof(struct QSEECom_ion_fd_info));
    ion_fd_info.data[0].fd = ihandle.ifd_data_fd;
    ion_fd_info.data[0].cmd_buf_offset = 4;

    send_cmd->cmd_id = FPC_GET_DB_DATA;
    send_cmd->v_addr = (intptr_t) ihandle.ion_sbuffer;
    send_cmd->length = length;
    send_cmd->extra = 0x00;

    memset((unsigned char *)ihandle.ion_sbuffer, 0, length);

    int ret = qsee_handle->send_modified_cmd(handle,send_cmd,64,rec_cmd,64,&ion_fd_info);

    if(ret < 0) {
        qsee_handle->ion_free(&ihandle);
        return -1;
    }

    if (send_cmd->v_addr != 0) {
        ALOGE("Error on TZ\n");
        qsee_handle->ion_free(&ihandle);
        return -1;
    }


    FILE *f = fopen(path, "w");

    if (f == NULL) {
        ALOGE("Error opening file : %s", path);
        return -1;
    }

    fwrite(ihandle.ion_sbuffer, length, 1, f);

    fclose(f);

    qsee_handle->ion_free(&ihandle);
    return 0;
}

err_t kitakami_fpc_set_gid(fpc_imp_data_t __unused *data, uint32_t __unused gid)
{
    // Not used on kitakami
    return 0;
};

err_t kitakami_fpc_close(fpc_imp_data_t **pData)
{
    ALOGD(__func__);
    fpc_data_t *ldata = (fpc_data_t*)*pData;
    ldata->qsee_handle->shutdown_app(&ldata->fpc_handle);
    if (kitakami_device_disable() < 0) {
        ALOGE("Error stopping device\n");
        return -1;
    }
    qsee_free_handle(&ldata->qsee_handle);
    free(ldata);
    *pData = NULL;
    return 1;
}

err_t kitakami_fpc_load_empty_db(fpc_imp_data_t *data) {
    fpc_data_t *ldata = (fpc_data_t*)data;
    struct QSEECom_handle *handle = ldata->fpc_handle;
    struct qsee_handle_t *qsee_handle = ldata->qsee_handle;

    qsee_handle->set_bandwidth(handle, true);

    if (kitakami_send_normal_command(ldata, FPC_INIT_NEW_DB,0) != 0) {
        ALOGE("Error sending FPC_INIT_NEW_DB to tz\n");
        return -1;
    }

    if (kitakami_send_normal_command(ldata, FPC_SET_FP_STORE,0) != 0) {
        ALOGE("Error sending FPC_SET_FP_STORE to tz\n");
        return -2;
    }

    qsee_handle->set_bandwidth(handle, false);
    return 0;
}

err_t kitakami_fpc_init(fpc_imp_data_t **data) {
    int ret = 0;

    struct QSEECom_handle * mFPC_handle = NULL;
    struct QSEECom_handle * mKeymasterHandle = NULL;
    struct qsee_handle_t* qsee_handle = NULL;

    ALOGE("INIT FPC TZ APP\n");

    if (qsee_open_handle(&qsee_handle) != 0) {
        ALOGE("Error loading QSEECom library");
        goto err;
    }

    if (kitakami_device_enable() < 0) {
        ALOGE("Error starting device\n");
        goto err_qsee;
    }

    fpc_data_t *fpc_data = (fpc_data_t*)malloc(sizeof(fpc_data_t));
    fpc_data->qsee_handle = qsee_handle;

    if (qsee_handle->load_trustlet(qsee_handle, &mKeymasterHandle, KM_TZAPP_PATH,
                             KM_TZAPP_NAME, 1024) < 0) {
        ALOGE("Could not load app %s\n", KM_TZAPP_NAME);
        goto err_alloc;
    }

    if (qsee_handle->load_trustlet(qsee_handle, &mFPC_handle, FP_TZAPP_PATH,
                                   FP_TZAPP_NAME, 1024) < 0) {
        ALOGE("Could not load app %s\n", FP_TZAPP_NAME);
        goto err_keymaster;
    }

    fpc_data->fpc_handle = mFPC_handle;

    // Start creating one off command to get cert from keymaster
    fpc_send_std_cmd_t *req = (fpc_send_std_cmd_t *) mKeymasterHandle->ion_sbuffer;
    req->cmd_id = 0x205;
    req->ret_val = 0x02;

    void * send_buf = mKeymasterHandle->ion_sbuffer;
    void * rec_buf = mKeymasterHandle->ion_sbuffer + 64;

    if (qsee_handle->send_cmd(mKeymasterHandle, send_buf, 64, rec_buf, 1024-64) < 0) {
        goto err_fpc;
    }
    /*qsee_handle->shutdown_app(&mKeymasterHandle);
    mKeymasterHandle = NULL;*/

    //Send command to keymaster
    fpc_send_std_cmd_t* ret_data = (fpc_send_std_cmd_t*) rec_buf;

    ALOGE("Keymaster Response Code : %u\n", ret_data->ret_val);
    ALOGE("Keymaster Response Length : %u\n", ret_data->length);

    void * data_buff = &ret_data->length + 1;

    if (kitakami_send_modified_command_to_tz(fpc_data, FPC_SET_INIT_DATA,data_buff,ret_data->length) < 0) {
        ALOGE("Error sending data to tz\n");
        goto err_fpc;
    }

    if (kitakami_send_normal_command(fpc_data, FPC_INIT,0) != 0) {
        ALOGE("Error sending FPC_INIT to tz\n");
        goto err_fpc;
    }

    if (kitakami_send_normal_command(fpc_data, FPC_GET_INIT_STATE,0) != 0) {
        ALOGE("Error sending FPC_GET_INIT_STATE to tz\n");
        goto err_fpc;
    }

    if (kitakami_send_normal_command(fpc_data, FPC_INIT_UNK_1,0) != 12) {
        ALOGE("Error sending FPC_INIT_UNK_1 to tz\n");
        goto err_fpc;
    }

    if (kitakami_device_enable() < 0) {
        ALOGE("Error starting device\n");
        goto err_fpc;
    }

    if (kitakami_send_normal_command(fpc_data, FPC_INIT_UNK_2,0) != 0) {
        ALOGE("Error sending FPC_INIT_UNK_2 to tz\n");
        goto err_fpc;
    }

    int fpc_info = kitakami_send_normal_command(fpc_data, FPC_INIT_UNK_0,0);

    ALOGI("Got device data : %d \n", fpc_info);

    if (kitakami_device_disable() < 0) {
        ALOGE("Error stopping device\n");
        goto err_fpc;
    }

    *data = (fpc_imp_data_t*)fpc_data;
    return 1;

err_fpc:
    if(mFPC_handle != NULL)
        qsee_handle->shutdown_app(&mFPC_handle);
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

char* kitakami_fpc_get_name(fpc_imp_data_t *data) {
    return "Kitakami 6.x FPC";
}

static struct fpc_imp_func_t loire_imp_functions = {
    .fpc_get_name = kitakami_fpc_get_name,
    .fpc_load_db_id = kitakami_fpc_load_db_id,
    .fpc_load_auth_challenge = kitakami_fpc_load_auth_challenge,
    .fpc_set_auth_challenge = kitakami_fpc_set_auth_challenge,
    .fpc_verify_auth_challenge = kitakami_fpc_verify_auth_challenge,
    .fpc_get_hw_auth_obj = kitakami_fpc_get_hw_auth_obj,
    .fpc_get_print_count = kitakami_fpc_get_print_count,
    .fpc_del_print_id = kitakami_fpc_del_print_id,
    .fpc_get_print_index = kitakami_fpc_get_print_index,
    .fpc_capture_image = kitakami_fpc_capture_image,
    .fpc_enroll_step = kitakami_fpc_enroll_step,
    .fpc_enroll_start = kitakami_fpc_enroll_start,
    .fpc_enroll_end = kitakami_fpc_enroll_end,
    .fpc_auth_start = kitakami_fpc_auth_start,
    .fpc_auth_step = kitakami_fpc_auth_step,
    .fpc_auth_end = kitakami_fpc_auth_end,
    .fpc_get_user_db_length = kitakami_fpc_get_user_db_length,
    .fpc_set_gid = kitakami_fpc_set_gid,
    .fpc_load_user_db = kitakami_fpc_load_user_db,
    .fpc_load_empty_db = kitakami_fpc_load_empty_db,
    .fpc_store_user_db = kitakami_fpc_store_user_db,
    .fpc_close = kitakami_fpc_close,
    .fpc_init = kitakami_fpc_init,
    .per_db_gid = true,
};

void fpc_kitakami_init_func(fpc_imp_func_t **func){

    //Can alloc dinamically as well if needed
    //fpc_imp_func_t *functions = malloc(sizeof(fpc_imp_func_t));
    //functions->get_name = fpc_loire_get_imp_name;

    *func = &loire_imp_functions;
}
