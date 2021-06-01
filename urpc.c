#include "urpc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <zf_log.h>

#include "config.h"
#include "uri.h"
#include "synchronizer.h"
#ifdef URPC_ENABLE_SERIAL
#include "devserial/devserial.h"
#endif
#ifdef URPC_ENABLE_XINET
#include "devxinet/devxinet.h"
#endif
#ifdef URPC_ENABLE_VIRTUAL
#include "devvirtual.h"
#endif

#ifdef _MSC_VER
#pragma warning( disable : 4311 ) // because we may cast 64-bit handle ptrs to uint32_t to use as pseudo-ids
#endif


#if !defined(URPC_ENABLE_SERIAL) && !defined(URPC_ENABLE_XINET) && !defined(URPC_ENABLE_VIRTUAL)
#error "Define at least one of URPC_ENABLE_SERIAL, URPC_ENABLE_XINET, URPC_ENABLE_VIRTUAL."
#endif // !defined(URPC_ENABLE_SERIAL) && !defined(URPC_ENABLE_XINET) && !defined(URPC_ENABLE_VIRTUAL)


enum urpc_device_type_t {
#ifdef URPC_ENABLE_SERIAL
    URPC_DEVICE_TYPE_SERIAL,
#endif
#ifdef URPC_ENABLE_XINET
    URPC_DEVICE_TYPE_XINET,
#endif
#ifdef URPC_ENABLE_VIRTUAL
    URPC_URPC_DEVICE_TYPE_VIRTUAL,
#endif
    URPC_DEVICE_TYPE_UNKNOWN
};


struct urpc_device_t {
    struct urpc_synchronizer_t *sync;
	enum urpc_device_type_t type;
    union {
#ifdef URPC_ENABLE_SERIAL
        struct urpc_device_serial_t *serial;
#endif
#ifdef URPC_ENABLE_XINET
        struct urpc_device_xinet_t *xinet;
#endif
#ifdef URPC_ENABLE_VIRTUAL
        struct virtual_device_t virtual;
#endif
    } impl;
};


static enum urpc_device_type_t
get_device_type_from_uri(const struct urpc_uri_t *parsed_uri)
{
#ifdef URPC_ENABLE_SERIAL
    if(!portable_strcasecmp(parsed_uri->scheme, "com"))
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
    memset(&parsed_uri, 0, sizeof(struct urpc_uri_t));
    if(urpc_uri_parse(uri, &parsed_uri))
    {
        ZF_LOGE("unknown device URI %s", uri);
        return NULL;
    }
    ZF_LOGD("URI %s resolved to dt '%s', host '%s' and path '%s' param '%s'='%s'", uri, parsed_uri.scheme, parsed_uri.host, parsed_uri.path, parsed_uri.paramname, parsed_uri.paramvalue);

    struct urpc_device_t *device = malloc(sizeof(struct urpc_device_t));
    if(device == NULL)
    {
        ZF_LOGE("failed to allocate memory for device");
        goto device_malloc_failed;
    }

    if((device->sync = urpc_syncronizer_create()) == NULL)
    {
        ZF_LOGE("failed to create synchronizer");
        goto synchronizer_create_failed;
    }

    device->type = get_device_type_from_uri(&parsed_uri);
    switch(device->type)
    {
#ifdef URPC_ENABLE_SERIAL
        case URPC_DEVICE_TYPE_SERIAL:
//            if(strlen(parsed_uri.host) != 0 || strlen(parsed_uri.path) == 0)
//            {
//                ZF_LOGE("Unknown device URI, only path should be specified");
//                goto device_impl_create_failed;
//            }
            if((device->impl.serial = urpc_device_serial_create(parsed_uri.path)) == NULL)
            {
                ZF_LOGE("failed to create serial device");
                goto device_impl_create_failed;
            }
            break;
#endif
#ifdef URPC_ENABLE_XINET
        case URPC_DEVICE_TYPE_XINET:
            if((device->impl.xinet = urpc_device_xinet_create(parsed_uri.host, parsed_uri.path)) == NULL)
            {
                ZF_LOGE("failed to create xinet device");
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
urpc_result_t
urpc_device_send_request(
	struct urpc_device_t *device,
    const char cid[URPC_CID_SIZE],
	const uint8_t *request,
	uint8_t request_len,
	uint8_t *response,
    uint8_t response_len
)
{
    if(device == NULL)
    {
        return urpc_result_nodevice;
    }

    urpc_result_t result;

    if(urpc_synchronizer_acquire(device->sync) != 0)
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
            result = urpc_device_xinet_send_request(device->impl.xinet, cid, request, request_len, response, response_len);
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

    if(urpc_synchronizer_release(device->sync) != 0)
    {
        ZF_LOGE("can't release device lock");
        return urpc_result_error;
    }

    return result;
}

// can be called from any thread; will return only after all in-flight requests has been completed;
// calling this function more then once per device is undefined behaviour
urpc_result_t
urpc_device_destroy(
        struct urpc_device_t *device
)
{
    if(device == NULL)
    {
        return urpc_result_nodevice;
    }

    if(urpc_synchronizer_destroy(device->sync) != 0)
    {
        ZF_LOGE("can't destroy device lock");
        return urpc_result_error;
    }

    urpc_result_t result;
    switch(device->type)
    {
#ifdef URPC_ENABLE_SERIAL
        case URPC_DEVICE_TYPE_SERIAL:
            result = urpc_device_serial_destroy(device->impl.serial);
            device->impl.serial = NULL;
            break;
#endif
#ifdef URPC_ENABLE_XINET
        case URPC_DEVICE_TYPE_XINET:
            result = urpc_device_xinet_destroy(device->impl.xinet);
            device->impl.xinet = NULL;
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

    // TODO: Unconditional free!
    free(device);
    return result;
}
