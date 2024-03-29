#include <sys/socket.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <string.h>
#include <errno.h>

#include <zf_log.h>

#include "platform.h"

urpc_result_t
urpc_udp_port_open(
    const char *host,
    int port,
    urpc_handle_t *handle
)
{
    // Creating socket file descriptor
    if ( (handle->socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        ZF_LOGE("socket creation failed");
        return urpc_result_error;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = URPC_SOCKET_TIMEOUT_SEC;
    tv.tv_usec = 0;
    int res = setsockopt(handle->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (res < 0)
    {
        ZF_LOGE("unable to set socket option %i", res);
        close(handle->socket);
        return urpc_result_error;
    }


    // Filling server information
    memset(&(handle->addr), 0, sizeof(handle->addr));

    handle->addr.sin_family = AF_INET;
    handle->addr.sin_port = htons(port);
    handle->addr.sin_addr.s_addr = inet_addr(host);

    return urpc_result_ok;
}

urpc_result_t
urpc_udp_port_close(
    urpc_handle_t handle
)
{
    close(handle.socket);
    return urpc_result_ok;
}

urpc_result_t
urpc_udp_port_flush(urpc_handle_t handle
   )
{
    (void)handle; // to avoid warinig of unused par
    return urpc_result_ok;
}

urpc_result_t
urpc_udp_port_write(
    urpc_handle_t handle,
    const void *buf,
    size_t *amount
)
{
    int res = sendto(handle.socket, (const char*)buf, *amount, 0, (const struct sockaddr *) &handle.addr, sizeof(handle.addr));

    if (res < 0)
    {
        ZF_LOGE("unable to send data, error %i", errno);
        return urpc_result_error;
    }

    return urpc_result_ok;
}

urpc_result_t
urpc_read_udp_port(
    urpc_handle_t handle,
    void *buf,
    size_t *amount
)
{
    socklen_t addrlen = (socklen_t)sizeof(handle.addr);
    struct sockaddr addr;
    memcpy(&addr, &handle.addr, sizeof(handle.addr));

    int res = recvfrom(handle.socket, (char*)buf, *amount, MSG_TRUNC, &addr, &addrlen);
    if (res < 0)
    {
        int error = errno;
        ZF_LOGE("unable to read socket, error %i", error);

        if (error == EAGAIN)
        {
            return urpc_result_timeout;
        }
        
        return urpc_result_error;
    }
    if (res > (int)*amount)
    {
        ZF_LOGE("too many data received from socket");
        return urpc_result_error;
    }
    
    *amount = res;

    return urpc_result_ok;
}
