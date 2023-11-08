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
    common.c

# ---------------- FPC ----------------
ifeq ($(filter-out loire tone,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_loire_tone.c
HAS_FPC := true
endif

ifeq ($(filter-out yoshino,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
HAS_FPC := true
LOCAL_CFLAGS += \
    -DUSE_FPC_YOSHINO
endif

ifeq ($(filter-out nile,$(SOMC_PLATFORM)),)
# NOTE: Nile can have either FPC or Egistec
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
HAS_FPC := true
LOCAL_CFLAGS += \
    -DUSE_FPC_NILE \
    -DHAS_LEGACY_EGISTEC
endif

ifeq ($(filter-out tama,$(SOMC_PLATFORM)),)
LOCAL_SRC_FILES += fpc_imp_yoshino_nile_tama.c
HAS_FPC := true
LOCAL_CFLAGS += \
    -DUSE_FPC_TAMA
endif

# ---------------- Egistec ----------------
ifneq ($(filter-out loire tone yoshino tama,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += -DFINGERPRINT_TYPE_EGISTEC
endif

# Firmware custom location
ifeq ($(filter-out kumano seine edo sagami nagara yodo,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += \
    -DEGIS_QSEE_APP_PATH=\"/odm/firmware\"
endif

# Firmware name and atributes
ifeq ($(filter-out kumano seine edo sagami lena murray,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += \
    -DEGISTEC_SAVE_TEMPLATE_RETURNS_SIZE \
    -DEGIS_QSEE_APP_NAME=\"egista\"
else ifeq ($(filter-out nagara,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += \
    -DEGISTEC_SAVE_TEMPLATE_RETURNS_SIZE \
    -DEGIS_QSEE_APP_NAME=\"egista64\"
else ifeq ($(filter-out zambezi yodo,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += \
    -DEGISTEC_SAVE_TEMPLATE_RETURNS_SIZE \
    -DEGIS_QSEE_APP_NAME=\"egisap\"
else
LOCAL_CFLAGS += \
    -DEGIS_QSEE_APP_NAME=\"egisap32\"
endif

# Define dynamic power management for everything but the following platforms:
ifneq ($(filter-out kumano seine,$(SOMC_PLATFORM)),)
LOCAL_CFLAGS += -DHAS_DYNAMIC_POWER_MANAGEMENT
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
    libdmabufheap \
    libhardware \
    libhidlbase \
    liblog \
    libutils

ifeq ($(TARGET_COMPILE_WITH_MSM_KERNEL),true)
LOCAL_C_INCLUDES += $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr
endif

LOCAL_CFLAGS += \
    -DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION) \
    -fexceptions

include $(BUILD_EXECUTABLE)
endif
endif # PRODUCT_PLATFORM_SOD
