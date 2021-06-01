
#include <string.h>

#include <zf_log.h>

#include "platform.h"

urpc_result_t
urpc_udp_port_open(
    const char *host,
    int port,
    urpc_handle_t *handle
)
{
    WSADATA wsa;

    // Initializing Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        ZF_LOGE("Winsock initialization failed, error %i", WSAGetLastError());
        return urpc_result_error;
    }

    // Creating socket file descriptor
    if ( (handle->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR ) {
        ZF_LOGE("socket creation failed, error %i", WSAGetLastError());
        WSACleanup();
        return urpc_result_error;
    }

    // Set socket timeout
    int timeout = URPC_SOCKET_TIMEOUT_SEC * 1000; // msec
    int res = setsockopt(handle->socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(int));
    if (res == SOCKET_ERROR)
    {
        ZF_LOGE("unable to set socket option, error %i", WSAGetLastError());
        closesocket(handle->socket);
        WSACleanup();
        return urpc_result_error;
    }
    res = setsockopt(handle->socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(int));
    if (res == SOCKET_ERROR)
    {
        ZF_LOGE("unable to set socket option, error %i", WSAGetLastError());
        closesocket(handle->socket);
        WSACleanup();
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
    closesocket(handle.socket);
    WSACleanup();
    return urpc_result_ok;
}

urpc_result_t
urpc_udp_port_flush(
    urpc_handle_t handle
)
{
    return urpc_result_ok;
}

urpc_result_t
urpc_udp_port_write(
    urpc_handle_t handle,
    const void *buf,
    size_t *amount
)
{
    int res = sendto(handle.socket, (const char*)buf, (int)(*amount), 0, (const struct sockaddr *) &handle.addr, sizeof(handle.addr));

    if (res == SOCKET_ERROR)
    {
        ZF_LOGE("unable to send data, error %i", WSAGetLastError());
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
    int addrlen = sizeof(handle.addr);
    struct sockaddr addr;
    memcpy(&addr, &handle.addr, sizeof(handle.addr));

    int res = recvfrom(handle.socket, (char*)buf, (int)(*amount), 0, &addr, &addrlen);
    if (res == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        ZF_LOGE("unable to read socket, error %i", error);
        if (error == WSAETIMEDOUT)
        {
            return urpc_result_timeout;
        }
        return urpc_result_error;
    }
    if (res == 0 && *amount > 0)
    {
        ZF_LOGE("no data received from socket");
        return urpc_result_error;
    }
    
    *amount = res;

    return urpc_result_ok;
}