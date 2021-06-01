#ifndef URPC_DEVXINET_DEVXINET_H
#define URPC_DEVXINET_DEVXINET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../urpc.h"


struct urpc_device_xinet_t;

struct urpc_device_xinet_t *
urpc_device_xinet_create(
        const char *host,
        const char *path
);

urpc_result_t
urpc_device_xinet_send_request(
        struct urpc_device_xinet_t *device,
        const char request_cid[URPC_CID_SIZE],
        const uint8_t *request,
        uint8_t request_len,
        uint8_t *response,
        uint8_t response_len
);

urpc_result_t
urpc_device_xinet_destroy(
        struct urpc_device_xinet_t *device
);

#ifdef __cplusplus
}
#endif

#endif //URPC_DEVXINET_DEVXINET_H
