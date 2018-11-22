#include "EgisFpDevice.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "FormatException.hpp"

struct ioctl_cmd {
    int interurpt_mode;
    int detect_period;
    int detect_threshold;
};

EgisFpDevice::EgisFpDevice() {
    mFd = open(DEV_PATH, O_RDWR);

    if (mFd < 0)
        throw FormatException("Failed to open fingerprint device! fd=%d, strerror=%s", mFd, strerror(errno));
}

EgisFpDevice::~EgisFpDevice() {
    if (mFd)
        close(mFd);
    mFd = 0;
}

int EgisFpDevice::Reset() {
    return ioctl(mFd, IOC_SENSOR_RESET);
}

int EgisFpDevice::EnableInterrupt() {
    ioctl_cmd cmd = {0, 1, 1};
    return ioctl(mFd, IOC_INTERRUPT_TRIGGER_INIT, &cmd);
}

int EgisFpDevice::DisableInterrupt() {
    return ioctl(mFd, IOC_INTERRUPT_TRIGGER_CLOSE);
}

/**
 * Returns true when a POLLIN event was triggered
 * (meaning something happened on the fp device).
 */
bool EgisFpDevice::WaitInterrupt(int timeout) {
    struct pollfd pfd = {.fd = mFd, .events = POLLIN};
    int rc = poll(&pfd, 1, timeout);
    if (rc == -1)
        throw FormatException("Poll error");
    return rc && pfd.revents & POLLIN;
}

int EgisFpDevice::GetDescriptor() const {
    return mFd;
}