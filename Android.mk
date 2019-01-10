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
    common.c

ifeq ($(filter-out loire tone,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_loire_tone.c
endif

ifeq ($(filter-out yoshino,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
endif

ifeq ($(filter-out nile,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
LOCAL_CFLAGS += -DUSE_FPC_NILE
endif

ifeq ($(filter-out tama,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
LOCAL_CFLAGS += -DUSE_FPC_TAMA
endif

LOCAL_STATIC_LIBRARIES := \
    android.hardware.biometrics.fingerprint@2.1-impl

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    liblog \
    libhidlbase \
    libhidltransport \
    libhardware \
    libutils \
    libdl \
    android.hardware.biometrics.fingerprint@2.1

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
