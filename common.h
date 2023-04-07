#ifndef FINGERPRINT_COMMON_H
#define FINGERPRINT_COMMON_H

#include <stdint.h>

#define FPC_IOC_MAGIC 0x1145
#define FPC_IOCWPREPARE _IOW(FPC_IOC_MAGIC, 0x01, int)
#define FPC_IOCWDEVWAKE _IOW(FPC_IOC_MAGIC, 0x02, int)
#define FPC_IOCWRESET _IOW(FPC_IOC_MAGIC, 0x03, int)
#define FPC_IOCWAWAKE _IOW(FPC_IOC_MAGIC, 0x04, int)
#define FPC_IOCRPREPARE _IOR(FPC_IOC_MAGIC, 0x81, int)
#define FPC_IOCRDEVWAKE _IOR(FPC_IOC_MAGIC, 0x82, int)
#define FPC_IOCRIRQ _IOR(FPC_IOC_MAGIC, 0x83, int)
#define FPC_IOCRIRQPOLL _IOR(FPC_IOC_MAGIC, 0x84, int)

enum {
    FPC_PWROFF = 0,
    FPC_PWRON = 1,
};

enum {
    FPC_EVENT_FINGER,
    FPC_EVENT_EVENTFD,
    FPC_EVENT_TIMEOUT,
    FPC_EVENT_ERROR,
};

typedef struct {
    int epoll_fd;
    int dev_fd;
    int event_fd;
} fpc_event_t;

typedef int32_t err_t;

err_t fpc_event_create(fpc_event_t *, int event_fd);
err_t fpc_event_destroy(fpc_event_t *);
err_t fpc_set_power(const fpc_event_t *, int poweron);
err_t fpc_get_power(const fpc_event_t *);
err_t fpc_poll_event(const fpc_event_t *);
err_t is_event_available(const fpc_event_t *event);
/**
 * Extend wakelock timeout.
 *
 * @param[in] awake   Boolean: awake or release wakelock.
 * @param[in] timeout How long to stay awake, in ms.
 *
 * The kernel cannot guess how long the operation takes, since the
 * HAL waits for a finger to disappear when the operation is unsuccessful,
 * before returning back to polling.
 *
 * Note that \p timeout is clamped to a maximum defined in the driver.
 */
err_t fpc_keep_awake(const fpc_event_t *event, int awake, unsigned int timeout);

#endif  // FINGERPRINT_COMMON_H
