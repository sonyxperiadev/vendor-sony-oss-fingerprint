#include "UInput.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "FPC UInput"
#include <log/log.h>

#define UINPUT_FPC_DEVICE_NAME "uinput-fpc"

UInput::UInput() {
    int rc = fpc_uinput_create(&uinput);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to setup uinput: %d", rc);
}

UInput::~UInput() {
    int rc = fpc_uinput_destroy(&uinput);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to destroy uinput: %d", rc);
}

void UInput::Click(unsigned short keycode) {
    int rc = fpc_uinput_click(&uinput, keycode);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to write uinput event: %d", rc);
}

int fpc_uinput_create(fpc_uinput_t *uinput) {
    int rc = 0;
    struct uinput_setup usetup = {
        .id.bustype = BUS_VIRTUAL,
    };
    // This name must match the keylayout/idc filename in /vendor/usr/{keylayout,idc}:
    strcpy(usetup.name, UINPUT_FPC_DEVICE_NAME);

    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);

    if (fd == -1) {
        ALOGE("Failed to open /dev/uinput: errno=%d", errno);
        return errno;
    }

    rc |= ioctl(fd, UI_SET_EVBIT, EV_KEY);
    rc |= ioctl(fd, UI_SET_KEYBIT, KEY_LEFT);
    rc |= ioctl(fd, UI_SET_KEYBIT, KEY_DOWN);
    rc |= ioctl(fd, UI_SET_KEYBIT, KEY_UP);
    rc |= ioctl(fd, UI_SET_KEYBIT, KEY_RIGHT);

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
        ALOGW("Failed to setup uinput device! rc=%d: %s, falling back to write.", rc, strerror(errno));

        struct uinput_user_dev usetup_legacy = {
            .id.bustype = BUS_VIRTUAL,
        };

        strcpy(usetup_legacy.name, UINPUT_FPC_DEVICE_NAME);

        rc = TEMP_FAILURE_RETRY(write(fd, &usetup_legacy, sizeof(usetup_legacy)));
        if (rc < 0) {
            ALOGE("Failed to setup uinput device! rc=%d: %s", rc, strerror(errno));
            close(fd);
            return rc;
        } else if (rc != sizeof(usetup_legacy)) {
            ALOGE("Didn't write full usetup_legacy, only %d/%zu bytes!", rc, sizeof(usetup_legacy));
            /* The kernel _should_ always accept the full object. */
            close(fd);
            return -EBUSY;
        }
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

int fpc_uinput_destroy(fpc_uinput_t *uinput) {
    int rc = ioctl(uinput->fd, UI_DEV_DESTROY);
    if (rc < 0)
        ALOGE("Failed to close uinput device! rc=%d: %s", rc, strerror(errno));
    close(uinput->fd);
    uinput->fd = -1;
    return 0;
}

static int fpc_write_input_event(const fpc_uinput_t *uinput, unsigned short type,
                                 unsigned short code, int value) {
    struct input_event ie = {
        .type = type,
        .code = code,
        .value = value,
    };

    int written = write(uinput->fd, &ie, sizeof(ie));
    if (written < 0) {
        ALOGE("Failed to write legacy uinput setup! rc=%d: %s", written, strerror(errno));
        return -1;
    } else if (written != sizeof(ie)) {
        ALOGE("Didn't write full input_event, only %d/%zu bytes!", written, sizeof(ie));
        return -1;
    }

    return 0;
}

/**
 * Send an input event followed by a synchronize.
 */
int fpc_uinput_send(const fpc_uinput_t *uinput, unsigned short keycode, unsigned short value) {
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
int fpc_uinput_click(const fpc_uinput_t *uinput, unsigned short keycode) {
    int rc = 0;
    rc |= fpc_write_input_event(uinput, EV_KEY, keycode, 1);
    rc |= fpc_write_input_event(uinput, EV_KEY, keycode, 0);
    rc |= fpc_write_input_event(uinput, EV_SYN, SYN_REPORT, 0);
    ALOGE_IF(rc, "Failed to write uinput event: %d", rc);
    return rc;
}
