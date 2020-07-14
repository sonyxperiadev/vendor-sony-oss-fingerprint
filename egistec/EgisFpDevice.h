#pragma once

#include <sys/ioctl.h>

#define ET51X_IOC_MAGIC 0x1145
#define ET51X_IOC_R_BASE 0x80
#define ET51X_IOCWPREPARE _IOW(ET51X_IOC_MAGIC, 0x01, int)
#define ET51X_IOCWDEVWAKE _IOW(ET51X_IOC_MAGIC, 0x02, int)
#define ET51X_IOCWRESET _IOW(ET51X_IOC_MAGIC, 0x03, int)
#define ET51X_IOCWAWAKE _IOW(ET51X_IOC_MAGIC, 0x04, int)
#define ET51X_IOCRPREPARE _IOR(ET51X_IOC_MAGIC, ET51X_IOC_R_BASE + 0x01, int)
#define ET51X_IOCRDEVWAKE _IOR(ET51X_IOC_MAGIC, ET51X_IOC_R_BASE + 0x02, int)
#define ET51X_IOCRIRQ _IOR(ET51X_IOC_MAGIC, ET51X_IOC_R_BASE + 0x03, int)
#define ET51X_IOCRIRQPOLL _IOR(ET51X_IOC_MAGIC, ET51X_IOC_R_BASE + 0x04, int)
#define ET51X_IOCRHWTYPE _IOR(ET51X_IOC_MAGIC, ET51X_IOC_R_BASE + 0x05, int)

#define FP_HW_TYPE_EGISTEC 0
#define FP_HW_TYPE_FPC 1

namespace egistec {

enum class FpHwId {
    Egistec = FP_HW_TYPE_EGISTEC,
    Fpc = FP_HW_TYPE_FPC,
};

class EgisFpDevice {
    static constexpr auto DEV_PATH = "/dev/fingerprint";

    int mFd = -1;

   public:
    EgisFpDevice();
    ~EgisFpDevice();

    EgisFpDevice(EgisFpDevice &&);
    EgisFpDevice &operator=(EgisFpDevice &&);

    int Reset() const;
    /**
     * Turn on power to the hardware.
     */
    int Enable() const;
    /**
     * Disable hardware by removing power.
     */
    int Disable() const;
    bool WaitInterrupt(int timeout = -1) const;
    int GetFd() const;

    // TODO: Move/abstract this if we ever get more
    // platforms with multiple sensor types.
#ifdef HAS_LEGACY_EGISTEC
    /**
     * Retrieve hardware ID from the FPC driver.
     * Currently only has a meaning on the Nile platform,
     * which can have an FPC or Egistec sensor.
     * All other platforms do not support this call and will
     * return an error.
     */
    FpHwId GetHwId() const;
#endif
};

/**
 * Automatically enable and disable the device based on the
 * lifetime (and thus scope) of this object.
 */
template <typename T>
struct DeviceEnableGuard {
    const T &object;
    inline DeviceEnableGuard(const T &t) : object(t) {
        object.Enable();
    }

    inline ~DeviceEnableGuard() {
        object.Disable();
    }

    DeviceEnableGuard(DeviceEnableGuard &) = delete;
    DeviceEnableGuard &operator=(DeviceEnableGuard &) = delete;
};

}  // namespace egistec
