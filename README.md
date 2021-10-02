# Sony Fingerprint HAL #

This is an open android HAL to enable the use for the fingerprint authentication sensor on the sony platforms.
It makes use of the TrustZone (TZ) fingerprint application via the QSEECOM API (documented here https://android.googlesource.com/platform/hardware/qcom/keymaster/+/android-6.0.1_r26/QSEEComAPI.h)

## Overview ##

* This was based around the OnePlus Two TrustZone fingerprint HAL (found here https://github.com/CyanogenMod/android_device_oneplus_oneplus2/blob/cm-13.0/fingerprint)
* Extra information was obtained from the Nexus 6P (angler kernel driver) (found here https://android.googlesource.com/kernel/msm/+/3d0a564505ab8452e7e6f52b972db386cc2f5f69)
* Protocol information was verified as it passed through the QSEECOM API to linux kernel

## Rebuild and run quickly

```console
$ m android.hardware.biometrics.fingerprint@2.1-service.sony && adb sync && adb shell setprop ctl.restart fps_hal
```

On devices where `adb sync` tries to sync too much, in turn running out of inodes, push the binary directly. For PDX213 for example:

```console
$ m android.hardware.biometrics.fingerprint@2.1-service.sony && adb push out/target/product/pdx213/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service.sony vendor/bin/hw && adb shell setprop ctl.restart fps_hal
```

## License ##

Copyright (C) 2016 Shane Francis / Jens Andersen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
