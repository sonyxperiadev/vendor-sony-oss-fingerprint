ifeq ($(PRODUCT_PLATFORM_SOD),true)
ifneq ($(TARGET_DEVICE_NO_FPC), true)
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := android.hardware.biometrics.fingerprint@2.1-service.sony
LOCAL_INIT_RC := android.hardware.biometrics.fingerprint@2.1-service.sony.rc
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := \
    $(call all-subdir-cpp-files) \
    QSEEComFunc.c \
    ion_buffer.c \
    common.c

ifeq ($(filter-out loire tone,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_loire_tone.c
HAS_FPC := true
endif

ifeq ($(filter-out yoshino,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
HAS_FPC := true
LOCAL_CFLAGS += -DUSE_FPC_YOSHINO
endif

ifeq ($(filter-out nile,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
HAS_FPC := true
LOCAL_CFLAGS += -DUSE_FPC_NILE
endif

ifeq ($(filter-out tama,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
HAS_FPC := true
LOCAL_CFLAGS += -DUSE_FPC_TAMA
endif

ifeq ($(filter-out ganges,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += -DUSE_FPC_GANGES
endif

ifeq ($(filter-out kumano,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += -DUSE_FPC_KUMANO
endif

ifneq ($(HAS_FPC),true)
# This file heavily depends on fpc_ implementations from the
# above fpc_imp_* files. There is no sensible default file
# on some platforms, so just remove the file altogether:
LOCAL_SRC_FILES -= BiometricsFingerprint.cpp
endif

LOCAL_SHARED_LIBRARIES := \
    android.hardware.biometrics.fingerprint@2.1 \
    libcutils \
    libdl \
    libhardware \
    libhidlbase \
    libhidltransport \
    libion \
    liblog \
    libutils

LOCAL_CONLYFLAGS := -std=c99

ifeq ($(TARGET_COMPILE_WITH_MSM_KERNEL),true)
LOCAL_C_INCLUDES += $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr
endif

LOCAL_CFLAGS += \
    -DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION) \
    -fexceptions \
    -std=c++1z

include $(BUILD_EXECUTABLE)
endif
endif # PRODUCT_PLATFORM_SOD
