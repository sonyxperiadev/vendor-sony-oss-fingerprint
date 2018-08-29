#include "common.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#define LOG_TAG "FPC COMMON"

#include <cutils/log.h>
#include <sys/ioctl.h>

err_t fpc_set_power(int poweron)
{
    int fd, ret = -1;

    fd = open("/dev/fingerprint", O_RDWR);
    if (fd < 0) {
        ALOGE("Error opening FPC device\n");
        return -1;
    }
    ret = ioctl(fd, FPC_IOCWPREPARE, poweron);
    if (ret < 0) {
        ALOGE("Error preparing FPC device\n");
        close(fd);
        return -1;
    }
    close(fd);

    return 1;
}

err_t fpc_get_power(void)
{
    int fd, ret = -1;
    uint32_t reply = -1;

    fd = open("/dev/fingerprint", O_RDWR);
    if (fd < 0) {
        ALOGE("Error opening FPC device\n");
        return -1;
    }
    ret = ioctl(fd, FPC_IOCRPREPARE, &reply);
    if (ret < 0) {
        ALOGE("Error preparing FPC device\n");
        close(fd);
        return -1;
    }
    close(fd);

    if (reply > 1)
        return -1;

    return reply;
}

err_t fpc_poll_irq(void)
{
    int fd, ret = -1;
    uint32_t arg = 0;

    fd = open("/dev/fingerprint", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        ALOGE("Error opening FPC device\n");
        return -1;
    }

    ret = ioctl(fd, FPC_IOCRIRQPOLL, &arg);
    if (ret < 0) {
        ALOGE("Error polling FPC device\n");
        close(fd);
        return -1;
    }
    close(fd);

    ALOGV("Interrupt status: %d\n", arg);

    /* 0 means that the interrupt didn't fire */
    if (arg == 0)
        return -1;

    return (err_t)arg;
}

err_t sysfs_write(char *path, char *s)
{
    char buf[80];
    ssize_t len;
    int ret = 0;
    int fd = open(path, O_WRONLY);

    if (fd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error opening %s: %s\n", path, buf);
        return -1 ;
    }

    len = write(fd, s, strlen(s));
    if (len < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error writing to %s: %s\n", path, buf);

        ret = -1;
    }

    close(fd);

    return ret;
}

err_t sys_fs_irq_poll(char *path)
{

    char buf[80];
    int ret = 0;
    int result;
    struct pollfd pollfds[2];

    pollfds[0].fd = open(path, O_RDONLY | O_NONBLOCK);

    if (pollfds[0].fd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error opening %s: %s\n", path, buf);
        return -1 ;
    }

    char dummybuf;
    read(pollfds[0].fd, &dummybuf, 1);
    pollfds[0].events = POLLPRI;

    result = poll(pollfds, 1, 1000);

    switch (result) {
        case 0:
            ALOGD ("timeout\n");
            close(pollfds[0].fd);
            return -1;
        case -1:
            ALOGE ("poll error \n");
            close(pollfds[0].fd);
            return -1;
        default:
            ALOGD ("IRQ GOT \n");
            close(pollfds[0].fd);
            break;
    }

    close(pollfds[0].fd);

    return ret;
}
