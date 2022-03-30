#include "urpc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <zf_log.h>

#include "config.h"
#include "uri.h"
#include "synchronizer.h"

#define URPC_ENABLE_XINET // to test
#define URPC_ENABLE_XIBRIDGE

#ifdef URPC_ENABLE_SERIAL
    #include "devserial/devserial.h"
#endif
#ifdef URPC_ENABLE_XINET
    #ifdef URPC_ENABLE_XIBRIDGE
       #include "../xibridge/client/xibridge.h"
       #define XIB_LENGTH 1024 + 16
    #else
       #include "devxinet/devxinet.h"
    #endif
#endif
#ifdef URPC_ENABLE_UDP
    #include "devudp/devudp.h"
#endif
#ifdef URPC_ENABLE_VIRTUAL
    #include "devvirtual.h"
#endif

#ifdef _MSC_VER
    #pragma warning( disable : 4311 ) // because we may cast 64-bit handle ptrs to uint32_t to use as pseudo-ids
#endif


#if !defined(URPC_ENABLE_SERIAL) && !defined(URPC_ENABLE_XINET) && !defined(URPC_ENABLE_VIRTUAL) && !defined(URPC_ENABLE_UDP)
    #error "Define at least one of URPC_ENABLE_SERIAL, URPC_ENABLE_XINET, URPC_ENABLE_VIRTUAL."
#endif // !defined(URPC_ENABLE_SERIAL) && !defined(URPC_ENABLE_XINET) && !defined(URPC_ENABLE_VIRTUAL)


enum urpc_device_type_t
{
    #ifdef URPC_ENABLE_SERIAL
    URPC_DEVICE_TYPE_SERIAL,
    #endif
    #ifdef URPC_ENABLE_XINET
    URPC_DEVICE_TYPE_XINET,
    #endif
    #ifdef URPC_ENABLE_VIRTUAL
    URPC_URPC_DEVICE_TYPE_VIRTUAL,
    #endif
    #ifdef URPC_ENABLE_UDP
    URPC_DEVICE_TYPE_UDP,
    #endif
    URPC_DEVICE_TYPE_UNKNOWN
};


struct urpc_device_t
{
    struct urpc_synchronizer_t *sync;
    enum urpc_device_type_t type;
    union
    {
        #ifdef URPC_ENABLE_SERIAL
        struct urpc_device_serial_t *serial;
        #endif
        #ifdef URPC_ENABLE_XINET
            #ifdef URPC_ENABLE_XIBRIDGE
                 unsigned int conn_id;
            #else
                 struct urpc_device_xinet_t *xinet;
            #endif
        #endif
        #ifdef URPC_ENABLE_UDP
        struct urpc_device_udp_t *udp;
        #endif
        #ifdef URPC_ENABLE_VIRTUAL
        struct virtual_device_t virtual;
        #endif
    } impl;
};


static enum urpc_device_type_t get_device_type_from_uri(const struct urpc_uri_t *parsed_uri)
{
    #ifdef URPC_ENABLE_SERIAL
    if (!portable_strcasecmp(parsed_uri->scheme, "com"))
    {
        return URPC_DEVICE_TYPE_SERIAL;
    }
    #endif
    #ifdef URPC_ENABLE_XINET
    if (!portable_strcasecmp(parsed_uri->scheme, "xi-net"))
    {
        return URPC_DEVICE_TYPE_XINET;
    }
    #endif
    #ifdef URPC_ENABLE_UDP
    if (!portable_strcasecmp(parsed_uri->scheme, "udp"))
    {
        return URPC_DEVICE_TYPE_UDP;
    }
    #endif
    #ifdef URPC_ENABLE_VIRTUAL
    if (!portable_strcasecmp(parsed_uri->scheme, "emu"))
    {
        return URPC_DEVICE_TYPE_VIRTUAL;
    }
    #endif
    return URPC_DEVICE_TYPE_UNKNOWN;
}

// can be called from any thread;
struct urpc_device_t *
urpc_device_create(
    const char *uri
)
{
    struct urpc_uri_t parsed_uri;
    #ifdef URPC_ENABLE_XIBRIDGE
        unsigned int xib_err;
        unsigned int xib_serial;
        uint8_t xib[XIB_LENGTH];
    #endif
    memset(&parsed_uri, 0, sizeof(struct urpc_uri_t));
    if (urpc_uri_parse(uri, &parsed_uri))
    {
        ZF_LOGE("unknown device URI %s", uri);
        return NULL;
    }
    ZF_LOGD("URI %s resolved to dt '%s', host '%s' and path '%s' param '%s'='%s'", uri, parsed_uri.scheme, parsed_uri.host, parsed_uri.path, parsed_uri.paramname, parsed_uri.paramvalue);

    struct urpc_device_t *device = malloc(sizeof(struct urpc_device_t));
    if (device == NULL)
    {
        ZF_LOGE("failed to allocate memory for device");
        goto device_malloc_failed;
    }

    if ((device->sync = urpc_syncronizer_create()) == NULL)
    {
        ZF_LOGE("failed to create synchronizer");
        goto synchronizer_create_failed;
    }

    device->type = get_device_type_from_uri(&parsed_uri);
    switch (device->type)
    {
            #ifdef URPC_ENABLE_SERIAL
        case URPC_DEVICE_TYPE_SERIAL:
//            if(strlen(parsed_uri.host) != 0 || strlen(parsed_uri.path) == 0)
//            {
//                ZF_LOGE("Unknown device URI, only path should be specified");
//                goto device_impl_create_failed;
//            }
            if ((device->impl.serial = urpc_device_serial_create(parsed_uri.path)) == NULL)
            {
                ZF_LOGE("failed to create serial device");
                goto device_impl_create_failed;
            }
            break;
            #endif
            #ifdef URPC_ENABLE_XINET
        case URPC_DEVICE_TYPE_XINET:
            #ifdef URPC_ENABLE_XIBRIDGE
                xib_serial = strtoul(parsed_uri.path, NULL, 10);
                if ((device->impl.conn_id = xibridge_open_device_connection(parsed_uri.host, xib_serial, 2, &xib_err)) == 0)
                {
                    xibridge_get_err_expl(xib, 1024 + 16, 0, xib_err);
                    ZF_LOGE("failed to create xinet device - %s", (char *)xib);
                    goto device_impl_create_failed;
                }
            #else
                if ((device->impl.xinet = urpc_device_xinet_create(parsed_uri.host, parsed_uri.path)) == NULL)
                {
                   ZF_LOGE("failed to create xinet device");
                   goto device_impl_create_failed;
                }
            #endif
            break;
            #endif
            #ifdef URPC_ENABLE_UDP
        case URPC_DEVICE_TYPE_UDP:
            if ((device->impl.udp = urpc_device_udp_create(parsed_uri.host, parsed_uri.port)) == NULL)
            {
                ZF_LOGE("failed to create udp device");
                goto device_impl_create_failed;
            }
            break;
            #endif
            #if URPC_ENABLE_VIRTUAL
        case URPC_DEVICE_TYPE_VIRTUAL:
            return close_port_virtual(&device->impl.virtual);
            break;
            #endif
        default:
            ZF_LOGE("unknown device type");
            goto device_impl_create_failed;
    }

    return device;

device_impl_create_failed:
    urpc_synchronizer_destroy(device->sync);

synchronizer_create_failed:
    free(device);

device_malloc_failed:
    return NULL;
}

// can be called from any thread;
// calling this function after urpc_device_destroy is undefined behaviour (where 'after' is defined by languages' memory model)
urpc_result_t urpc_device_send_request(
    struct urpc_device_t *device,
    const char cid[URPC_CID_SIZE],
    const uint8_t *request,
    uint8_t request_len,
    uint8_t *response,
    uint8_t response_len
)
{
    if (device == NULL)
    {
        return urpc_result_nodevice;
    }

    urpc_result_t result;
#ifdef URPC_ENABLE_XIBRIDGE
    unsigned int xib_err;
    uint8_t xib[XIB_LENGTH];
    int xib_result;
    unsigned int xib_status;
    memcpy(xib, cid, URPC_CID_SIZE);
    memcpy(xib + URPC_CID_SIZE, request, request_len);
#endif

    if (urpc_synchronizer_acquire(device->sync) != 0)
    {
        ZF_LOGE("can't acquire device lock");
        return urpc_result_nodevice;
    }

    switch (device->type)
    {
            #ifdef URPC_ENABLE_SERIAL
        case URPC_DEVICE_TYPE_SERIAL:
            result = urpc_device_serial_send_request(device->impl.serial, cid, request, request_len, response, response_len);
            break;
            #endif
            #ifdef URPC_ENABLE_XINET
        case URPC_DEVICE_TYPE_XINET:
            #ifdef URPC_ENABLE_XIBRIDGE
                xib_result = xibridge_device_request_response(device->impl.conn_id, xib, request_len + URPC_CID_SIZE, response, response_len, xib_status);
                if (xib_result != 0) // some positive
                {
                    result = xib_status;
                }
                else
                {
                    // this is possible common error
                    xib_err = xibridge_get_last_err_no(device->impl.conn_id);
                    xibridge_get_err_expl(xib, XIB_LENGTH, 0, xib_err);
                    ZF_LOGE("failed to request conn_id %u - %s", device->impl.conn_id, (const char*)xib);
                }
                #else
                result = urpc_device_xinet_send_request(device->impl.xinet, cid, request, request_len, response, response_len);
            #endif
            break;
            #endif
            #ifdef URPC_ENABLE_UDP
        case URPC_DEVICE_TYPE_UDP:
            result = urpc_device_udp_send_request(device->impl.udp, cid, request, request_len, response, response_len);
            break;
            #endif
            #ifdef URPC_ENABLE_VIRTUAL
        case URPC_DEVICE_TYPE_VIRTUAL:
            result = close_port_virtual(&device->impl.virtual);
            break;
            #endif
        default:
            result = urpc_result_error;
            break;
    }

    if (urpc_synchronizer_release(device->sync) != 0)
    {
        ZF_LOGE("can't release device lock");
        return urpc_result_error;
    }

    return result;
}

// can be called from any thread; will return only after all in-flight requests has been completed;
// calling this function more then once per device is undefined behaviour
urpc_result_t urpc_device_destroy(
    struct urpc_device_t **device_ptr
)
{
    struct urpc_device_t *device = *device_ptr;
    #ifdef URPC_ENABLE_XIBRIDGE
        unsigned int xib_err;
        unsigned int xib_status;
    #endif
    if (device == NULL)
    {
        return urpc_result_nodevice;
    }

    if (urpc_synchronizer_destroy(device->sync) != 0)
    {
        ZF_LOGE("can't destroy device lock");
        return urpc_result_error;
    }

    urpc_result_t result;
    switch (device->type)
    {
            #ifdef URPC_ENABLE_SERIAL
        case URPC_DEVICE_TYPE_SERIAL:
            result = urpc_device_serial_destroy(&device->impl.serial);
            break;
            #endif
            #ifdef URPC_ENABLE_XINET
        case URPC_DEVICE_TYPE_XINET:
             #ifdef URPC_ENABLE_XIBRIDGE
                xibridge_close_device_connection(device->impl.conn_id);
                result = urpc_result_ok; 
            #else
                result = urpc_device_xinet_destroy(&device->impl.xinet);
            #endif
            break;
            #endif
            #ifdef URPC_ENABLE_UDP
        case URPC_DEVICE_TYPE_UDP:
            result = urpc_device_udp_destroy(&device->impl.udp);
            break;
            #endif
            #if URPC_ENABLE_VIRTUAL
        case URPC_DEVICE_TYPE_VIRTUAL:
            result = close_port_virtual(&device->impl.virtual);
            break;
            #endif
        default:
            result = urpc_result_error;
            break;
    }
    if (result != urpc_result_ok)
    {
        return result;
    }
    free(device);

    *device_ptr = NULL;

    return urpc_result_ok;
}
