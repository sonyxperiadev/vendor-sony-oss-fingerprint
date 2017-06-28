#
# Copyright (C) 2016 Shane Francis / Jens Andersen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ifeq ($(filter-out satsuki sumire suzuran suzu kugo dora kagura keyaki maple,$(TARGET_DEVICE)),)
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := fingerprint.$(TARGET_DEVICE)
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := fingerprint.c \
		   QSEEComFunc.c \
		   common.c \
		   fpc_imp_kitakami.c \
		   fpc_imp_loire_tone.c \
		   fpc_imp_yoshino.c

ifeq ($(TARGET_FPC_VERSION),N)
LOCAL_CFLAGS += -DUSE_FPC_N
endif

LOCAL_CFLAGS += -std=c99
LOCAL_SHARED_LIBRARIES := liblog \
			  libdl \
			  libcutils \
			  libutils

SYSFS_PREFIX := "/sys/devices/soc/fpc1145_device"
ifeq ($(TARGET_KERNEL_VERSION),3.10)
SYSFS_PREFIX := "/sys/devices/soc.0/fpc1145_device"
endif
LOCAL_CFLAGS += -DSYSFS_PREFIX=\"$(SYSFS_PREFIX)\"

ifeq ($(TARGET_COMPILE_WITH_MSM_KERNEL),true)
LOCAL_C_INCLUDES += $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr
endif

LOCAL_CFLAGS += -DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION)

LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
endif
