/*
 * Copyright (C) 2018 Shane Francis / Jens Andersen
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

#ifndef ANDROID_HARDWARE_BIOMETRICS_FINGERPRINT_V2_1_BIOMETRICSFINGERPRINT_H
#define ANDROID_HARDWARE_BIOMETRICS_FINGERPRINT_V2_1_BIOMETRICSFINGERPRINT_H

#include <log/log.h>
#include <hardware/fingerprint.h>
#include <hidl/MQDescriptor.h>
#include <hidl/Status.h>
#include <pthread.h>
#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>
#include <mutex>
#include <condition_variable>
#include <sys/eventfd.h>

extern "C" {
    #include "fpc_imp.h"
}

namespace fpc {

using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;
using ::android::hardware::biometrics::fingerprint::V2_1::RequestStatus;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::sp;

enum worker_state {
    STATE_INVALID,
    /**
     * In idle state the thread eventually transitions into navigation mode,
     * where the sensor waits for navigation gestures from the user.
     */
    STATE_IDLE,
    /**
     * In pause state, the thread indefinitely blocks for future instructions.
     *
     * Useful to make sure the thread is not doing anything, such that the
     * current/main/service thread can touch the TZ (setup commands in
     * enroll() or authenticate() for example).
     */
    STATE_PAUSE,
    STATE_ENROLL,
    STATE_AUTH,
    STATE_EXIT,
};


typedef struct {
    pthread_t thread;
    bool thread_running;
    worker_state running_state;
    worker_state desired_state;
    int event_fd;
} fpc_thread_t;

typedef struct {
    fpc_thread_t worker;
    fpc_imp_data_t *fpc;
    uint32_t gid;
    char db_path[255];
    uint64_t challenge;
} sony_fingerprint_device_t;

struct BiometricsFingerprint : public IBiometricsFingerprint {
public:
    BiometricsFingerprint();
    ~BiometricsFingerprint();

    // Methods from ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint follow.
    Return<uint64_t> setNotify(const sp<IBiometricsFingerprintClientCallback>& clientCallback) override;
    Return<uint64_t> preEnroll() override;
    Return<RequestStatus> enroll(const hidl_array<uint8_t, 69>& hat, uint32_t gid, uint32_t timeoutSec) override;
    Return<RequestStatus> postEnroll() override;
    Return<uint64_t> getAuthenticatorId() override;
    Return<RequestStatus> cancel() override;
    Return<RequestStatus> enumerate() override;
    Return<RequestStatus> remove(uint32_t gid, uint32_t fid) override;
    Return<RequestStatus> setActiveGroup(uint32_t gid, const hidl_string& storePath) override;
    Return<RequestStatus> authenticate(uint64_t operationId, uint32_t gid) override;

private:
    static sony_fingerprint_device_t* openHal();
    static Return<RequestStatus> ErrorFilter(int32_t error);

    // Internal machinery to set the active group
    int __setActiveGroup(uint32_t gid);

    //Auth / Enroll thread functions
    bool startWorker();

    worker_state getNextState();
    bool isEventAvailable(int timeout = /* Do not block at all: */ 0);
    bool setState(worker_state);
    bool setState(worker_state, const std::unique_lock<std::mutex> &);
    bool waitForState(worker_state);
    bool pauseThread();
    bool resumeNavigation();
    static void * worker_thread(void *args);
    void workerThread();
    void processNavigation();
    void processEnroll();
    void processAuth();

    std::mutex mClientCallbackMutex;
    std::mutex mEventfdMutex;
    std::condition_variable mThreadStateChanged;
    sp<IBiometricsFingerprintClientCallback> mClientCallback;
    sony_fingerprint_device_t *mDevice;
    uint64_t auth_challenge;
};

}  // namespace fpc

#endif  // ANDROID_HARDWARE_BIOMETRICS_FINGERPRINT_V2_1_BIOMETRICSFINGERPRINT_H
