#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#if PLATFORM_SDK_VERSION >= 28
#include <bits/epoll_event.h>
#endif
#include <sys/epoll.h>

#define LOG_TAG "FPC COMMON"

#include <log/log.h>

#define EVENT_COUNT 2

err_t fpc_event_create(fpc_event_t *event, int event_fd)
{
    int fd = 0, rc;

    event->event_fd = event_fd;

    fd = open("/dev/fingerprint", O_RDWR);
    if (fd < 0) {
        ALOGE("Error opening FPC device");
        return -1;
    }
    event->dev_fd = fd;

    fd = epoll_create1(0);
    if (fd < 0) {
        ALOGE("Error creating epoll fd");
        return -1;
    }
    event->epoll_fd = fd;

    struct epoll_event ev = {
        .data.fd = event_fd,
        .events = EPOLLIN,
    };
    rc = epoll_ctl(event->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    if (rc) {
        ALOGE("Failed to add event_fd to epoll: %d", rc);
        return -1;
    }

    ev = (struct epoll_event){
        .data.fd = event->dev_fd,
        .events = EPOLLIN,
    };
    rc = epoll_ctl(event->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
    if (rc) {
        ALOGE("Failed to add event->dev_fd to epoll: %d", rc);
        return -1;
    }

    return 0;
}

err_t fpc_event_destroy(fpc_event_t *event)
{
    event->event_fd = -1;
    close(event->dev_fd);
    event->dev_fd = -1;
    close(event->epoll_fd);
    event->epoll_fd = -1;
    return 0;
}

err_t fpc_set_power(const fpc_event_t *event, int poweron)
{
    int ret = -1;

    ret = ioctl(event->dev_fd, FPC_IOCWPREPARE, poweron);
    if (ret < 0) {
        ALOGE("Failed preparing FPC device (%d) %s", ret, strerror(errno));
        return -1;
    }

    return 1;
}

err_t fpc_get_power(const fpc_event_t *event)
{
    int ret = -1;
    uint32_t reply = -1;

    ret = ioctl(event->dev_fd, FPC_IOCRPREPARE, &reply);
    if (ret < 0) {
        ALOGE("Failed reading device power state (%d) %s", ret, strerror(errno));
        return -1;
    }

    if (reply > 1)
        return -1;

    return reply;
}

err_t fpc_poll_event(const fpc_event_t *event)
{
    int cnt;

    struct epoll_event events[EVENT_COUNT];
    cnt = epoll_wait(event->epoll_fd, events, EVENT_COUNT, -1);

    if (cnt < 0) {
        ALOGE("Failed waiting for epoll: %d", cnt);
        return FPC_EVENT_ERROR;
    }

    if (!cnt) {
        ALOGE("Epoll timed out despite infinite blocking!");
        return FPC_EVENT_TIMEOUT;
    }

    for (int i = 0; i < cnt; ++i)
        if (events[i].data.fd == event->event_fd && events[i].events | EPOLLIN) {
            ALOGD("Waking up from eventfd");
            return FPC_EVENT_EVENTFD;
        }

    // Only other event source is the fingerprint.
    ALOGD("Waking up from finger event");
    return FPC_EVENT_FINGER;
}

/**
 * Checks if an event (request to switch to a different state) is available.
 *
 * Does not return true on (spurious) hardware/irq raise.
 */
err_t is_event_available(const fpc_event_t *event)
{
    int cnt;

    struct pollfd pfd = {
        .fd = event->event_fd,
        .events = POLLIN,
    };

    // 0 = do not block at all:
    cnt = poll(&pfd, 1, 0);

    if (cnt < 0) {
        ALOGE("Failed waiting for epoll: %d", cnt);
        return cnt;
    }

    return cnt > 0;
}

err_t fpc_keep_awake(const fpc_event_t *event, int awake, unsigned int timeout)
{
    struct {
        int awake;
        unsigned int timeout;
    } args = {awake, timeout};
    int rc = ioctl(event->dev_fd, FPC_IOCWAWAKE, &args);
    if (rc)
        ALOGE("%s failed: %d", __func__, rc);
    return rc;
}

err_t fpc_uinput_create(fpc_uinput_t *uinput)
{
    int rc = 0;
    struct uinput_setup usetup = {
        .id.bustype = BUS_VIRTUAL,
    };
    // This name must match the keylayout/idc filename in /vendor/usr/{keylayout,idc}:
    strcpy(usetup.name, "uinput-fpc");

    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);

    if (fd == -1) {
        ALOGE("Failed to open /dev/uinput: errno=%d", errno);
        return errno;
    }

    rc |= ioctl(fd, UI_SET_EVBIT, EV_KEY);
    rc |= ioctl(fd, UI_SET_KEYBIT, SYSTEM_NAVIGATION_LEFT);
    rc |= ioctl(fd, UI_SET_KEYBIT, SYSTEM_NAVIGATION_DOWN);
    rc |= ioctl(fd, UI_SET_KEYBIT, SYSTEM_NAVIGATION_UP);
    rc |= ioctl(fd, UI_SET_KEYBIT, SYSTEM_NAVIGATION_RIGHT);

    // See fpc_navi_poll: These keys are not used:
    /*
    rc |= ioctl(fd, UI_SET_KEYBIT, 0x133);
    rc |= ioctl(fd, UI_SET_KEYBIT, 0x134);

    rc |= ioctl(fd, UI_SET_KEYBIT, KEY_PROG3);
    rc |= ioctl(fd, UI_SET_KEYBIT, KEY_PROG4);
    */

    if (rc < 0) {
        ALOGE("Failed to set up event- or key_bit: rc=%d: %s", rc, strerror(errno));
        close(fd);
        return rc;
    }

    rc = ioctl(fd, UI_DEV_SETUP, &usetup);
    if (rc < 0) {
        ALOGE("Failed to setup uinput device! rc=%d: %s", rc, strerror(errno));
        close(fd);
        return rc;
    }

    rc = ioctl(fd, UI_DEV_CREATE);
    if (rc < 0) {
        ALOGE("Failed to create uinput device! rc=%d: %s", rc, strerror(errno));
        close(fd);
        return rc;
    }

    ALOGI("Successfully created uinput device! rc=%d", rc);

    uinput->fd = fd;
    return 0;
}

err_t fpc_uinput_destroy(fpc_uinput_t *uinput)
{
    int rc = ioctl(uinput->fd, UI_DEV_DESTROY);
    if (rc < 0)
        ALOGE("Failed to close uinput device! rc=%d: %s", rc, strerror(errno));
    close(uinput->fd);
    uinput->fd = -1;
    return 0;
}

static err_t fpc_write_input_event(const fpc_uinput_t *uinput, short type, short code, int value)
{
    struct input_event ie = {
        .type = type,
        .code = code,
        .value = value,
    };

    int written = write(uinput->fd, &ie, sizeof(ie));
    if (written != sizeof(ie)) {
        ALOGE("Didn't write full input_event, only %d/%zu bytes!", written, sizeof(ie));
        return -1;
    }

    return 0;
}

/**
 * Send an input event followed by a synchronize.
 */
err_t fpc_uinput_send(const fpc_uinput_t *uinput, short keycode, short value)
{
    int rc = 0;
    rc |= fpc_write_input_event(uinput, EV_KEY, keycode, value);
    rc |= fpc_write_input_event(uinput, EV_SYN, SYN_REPORT, 0);
    ALOGE_IF(rc, "Failed to write uinput event: %d", rc);
    return rc;
}

/**
 * Simulate a click with an input event down and up,
 * followed by a synchronize.
 */
err_t fpc_uinput_click(const fpc_uinput_t *uinput, short keycode)
{
    int rc = 0;
    rc |= fpc_write_input_event(uinput, EV_KEY, keycode, 1);
    rc |= fpc_write_input_event(uinput, EV_KEY, keycode, 0);
    rc |= fpc_write_input_event(uinput, EV_SYN, SYN_REPORT, 0);
    ALOGE_IF(rc, "Failed to write uinput event: %d", rc);
    return rc;
}
