#ifndef URPC_DEVUDP_DEVUDP_H
#define URPC_DEVUDP_DEVUDP_H

#include "../urpc.h"


struct urpc_device_udp_t;

struct urpc_device_udp_t *
urpc_device_udp_create(
    const char *host, int port
);

urpc_result_t
urpc_device_udp_send_request(
    struct urpc_device_udp_t *device,
    const char request_cid[URPC_CID_SIZE],
    const uint8_t *request,
    uint8_t request_len,
    uint8_t *response,
    uint8_t response_len
);

urpc_result_t
urpc_device_udp_destroy(
    struct urpc_device_udp_t **device_ptr
);

#endif //URPC_DEVUDP_DEVUDP_H
