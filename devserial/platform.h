#ifndef URPC_DEVSERIAL_PLATFORM_H
#define URPC_DEVSERIAL_PLATFORM_H

#include <time.h>
#ifdef _MSC_VER
    #define _CRT_SECURE_NO_WARNINGS
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    typedef HANDLE urpc_handle_t;
#else
    #include <unistd.h>
    typedef int urpc_handle_t;
#endif
#include "devserial.h"


// time to wait to open port for normal work
#define URPC_ZEROSYNC_TRIGGER_TIMEOUT 10000
// syncronization attempts count
#define URPC_ZEROSYNC_RETRY_COUNT 4
// time to wait before retry attempts
#define URPC_ZEROSYNC_RETRY_DELAY 200
// amount of zeroes to send in case of an error
#define URPC_ZEROSYNC_BURST_SIZE 64
// system timeout for port functions
#define URPC_PORT_TIMEOUT 500


/*
 * Platform-specific serial port routines
 */
urpc_result_t
urpc_serial_port_open(
    const char *path,
    urpc_handle_t *handle
);

urpc_result_t
urpc_serial_port_close(
    urpc_handle_t handle
);

urpc_result_t
urpc_serial_port_flush(
    urpc_handle_t handle
);

urpc_result_t
urpc_serial_port_write(
    urpc_handle_t handle,
    const void *buf,
    size_t *amount
);

urpc_result_t
urpc_read_serial_port(
    urpc_handle_t handle,
    void *buf,
    size_t *amount
);

/*
 * Misc
 */
void
urpc_msec_sleep(
    unsigned int msec
);

void
urpc_get_wallclock(
    time_t *sec,
    int *msec
);

#endif //URPC_DEVSERIAL_PLATFORM_H
