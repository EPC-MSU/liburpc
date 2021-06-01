#ifndef URPC_DEVUDP_PLATFORM_H
#define URPC_DEVUDP_PLATFORM_H

#include "ring.h"

#include <time.h>
#ifdef _MSC_VER
    #include <winsock2.h>
        typedef struct {
        SOCKET socket;
        struct sockaddr_in addr;
        buffer_t *socket_buffer;
    } urpc_handle_t;
#else
    #include <unistd.h>
    #include <arpa/inet.h>
        typedef struct {
        int socket;
        struct sockaddr_in addr;
        buffer_t *socket_buffer;
    } urpc_handle_t;
#endif

#include "devudp.h"


// time to wait to open port for normal work
#define URPC_ZEROSYNC_TRIGGER_TIMEOUT 10000
// syncronization attempts count
#define URPC_ZEROSYNC_RETRY_COUNT 4
// time to wait before retry attempts
#define URPC_ZEROSYNC_RETRY_DELAY 200
// amount of zeroes to send in case of an error
#define URPC_ZEROSYNC_BURST_SIZE 64
// system timeout for socket functions
#define URPC_SOCKET_TIMEOUT_SEC 3
// single UDP package maximum length
#define UDP_PACKAGE_BUFFER_SIZE 10000


/*
 * Platform-specific udp port routines
 */
urpc_result_t
urpc_udp_port_open(
    const char *host,
    int port,
    urpc_handle_t *handle
);

urpc_result_t
urpc_udp_port_close(
    urpc_handle_t handle
);

urpc_result_t
urpc_udp_port_flush(
    urpc_handle_t handle
);

urpc_result_t
urpc_udp_port_write(
    urpc_handle_t handle,
    const void *buf,
    size_t *amount
);

urpc_result_t
urpc_read_udp_port(
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

#endif //URPC_DEVUDP_PLATFORM_H
