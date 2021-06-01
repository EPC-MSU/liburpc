#include "platform.h"

#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <string.h>

#ifdef __APPLE__
    /* We need IOKit */
    #include <CoreFoundation/CoreFoundation.h>
    #include <IOKit/IOKitLib.h>
    #include <IOKit/usb/IOUSBLib.h>
    #include <sys/sysctl.h>
    /* and time too */
    #include <mach/clock.h>
    #include <mach/mach.h>
#endif

#include <zf_log.h>


/*
 * Serial port support
 */

urpc_result_t urpc_serial_port_open(
    const char *path,
    urpc_handle_t *handle
)
{
    urpc_handle_t opened_handle;

    opened_handle = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (opened_handle == -1)
    {
        ZF_LOGE("unable to open port %s: ", path);
        return urpc_result_error;
    }

    /* Consult an advisory lock */
    if (flock(opened_handle, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK)
    {
        close(opened_handle);
        ZF_LOGE("unable to open locked port %s: ", path);
        return urpc_result_error;
    }

    if (flock(opened_handle, LOCK_EX) == -1)
    {
        close(opened_handle);
        ZF_LOGE("unable to lock a port %s: ", path);
        return urpc_result_error;
    }


    /* Adjust settings */
    struct termios options;

    if (fcntl(opened_handle, F_SETFL, 0) == -1)
    {
        close(opened_handle);
        ZF_LOGE("error setting port settings: ");
        return urpc_result_error;
    }

    if (tcgetattr(opened_handle, &options) == -1)
    {
        close(opened_handle);
        ZF_LOGE("error getting port attrs: ");
        return urpc_result_error;
    }

    if (cfsetispeed(&options, B115200) == -1 || cfsetospeed(&options, B115200) == -1)
    {
        close(opened_handle);
        ZF_LOGE("error setting port speed: ");
        return urpc_result_error;
    }

    // set port flags
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    options.c_cflag |= (CLOCAL | CREAD);
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;
    options.c_cflag &= ~(PARENB | PARODD);
    options.c_cflag |= CSTOPB;
    options.c_cflag &= ~CRTSCTS;

    options.c_iflag &= ~(IXON | IXOFF | IXANY);
    options.c_iflag &= ~(INPCK | PARMRK | ISTRIP | IGNPAR);
    options.c_iflag &= ~(IGNBRK | BRKINT | INLCR | IGNCR | ICRNL | IMAXBEL);

    options.c_oflag &= ~OPOST;

    options.c_cc[VMIN] = 0;
    options.c_cc[VTIME] = URPC_PORT_TIMEOUT / 100;

    if (tcsetattr(opened_handle, TCSAFLUSH, &options) == -1)
    {
        close(opened_handle);
        ZF_LOGE("error setting port attrs: ");
        return urpc_result_error;
    }

    tcflush(opened_handle, TCIOFLUSH);

    *handle = opened_handle;

    return urpc_result_ok;
}

urpc_result_t urpc_serial_port_close(
    urpc_handle_t handle
)
{
    if (close(handle) == -1)
    {
        int error_code = errno;
        ZF_LOGE("error closing port: ");
        return (error_code == ENXIO || error_code == EIO) ? urpc_result_nodevice : urpc_result_error;
    }
    return urpc_result_ok;
}

urpc_result_t urpc_serial_port_flush(
    urpc_handle_t handle
)
{
    if (tcflush(handle, TCIOFLUSH))
    {
        int error_code = errno;
        ZF_LOGE("serial port flush failed: %s", strerror(error_code));
        return (error_code == ENXIO || error_code == EIO) ? urpc_result_nodevice : urpc_result_error;
    }
    return urpc_result_ok;
}

urpc_result_t urpc_read_serial_port(
    urpc_handle_t handle,
    void *buf,
    size_t *amount
)
{
    size_t want_to_read = *amount;
    ssize_t actually_read = read(handle, buf, want_to_read);
    if (actually_read == -1)
    {
        int error_code = errno;
        ZF_LOGE("serial port read failed: %s", strerror(error_code));
        return (error_code == ENXIO || error_code == EIO) ? urpc_result_nodevice : urpc_result_error;
    }

    *amount = (size_t)actually_read;
    return urpc_result_ok;
}

urpc_result_t urpc_serial_port_write(
    urpc_handle_t handle,
    const void *buf,
    size_t *amount
)
{
    size_t want_to_write = *amount;
    ssize_t actually_written = write(handle, buf, want_to_write);
    if (actually_written == -1)
    {
        int error_code = errno;
        ZF_LOGE("serial port write failed: %s", strerror(error_code));
        return (error_code == ENXIO || error_code == EIO) ? urpc_result_nodevice : urpc_result_error;
    }

    *amount = (size_t)actually_written;
    return urpc_result_ok;
}


/*
 * Misc
 */

void urpc_msec_sleep(
    unsigned int msec
)
{
    // POSIX 1.b
    struct timespec ts;
    ts.tv_sec = (time_t)(msec / 1E3);
    ts.tv_nsec = (long)(msec * 1E6 - ts.tv_sec * 1E9);
    if (nanosleep( &ts, NULL ) != 0)
    {
        ZF_LOGE("nanosleep failed: ");
    }
}

void urpc_get_wallclock_us(
    uint64_t *us
)
{
    struct timeval now;
    gettimeofday(&now, 0);
    if (us)
    {
        *us = now.tv_sec * 1000000 + now.tv_usec;
    }
}

void urpc_get_wallclock(
    time_t *sec, int *msec
)
{
    struct timeval now;
    gettimeofday(&now, 0);
    if (sec && msec)
    {
        *sec = now.tv_sec;
        *msec = now.tv_usec / 1000;
    }
}
