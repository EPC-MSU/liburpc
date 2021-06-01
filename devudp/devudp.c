#include "devudp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <zf_log.h>

#include "ring.h"

#include "platform.h"


struct urpc_device_udp_t
{
    urpc_handle_t handle;
};

static uint8_t errv_cid[URPC_CID_SIZE] = { 'e', 'r', 'r', 'v' };
static uint8_t errd_cid[URPC_CID_SIZE] = { 'e', 'r', 'r', 'd' };

static urpc_result_t command_port_send(urpc_handle_t handle, const uint8_t *command, size_t command_len)
{
    urpc_result_t result;
    size_t amount, k = 0;

    while (k < command_len)
    {
        amount = command_len - k;
        if (command_len < k)
        {
            return urpc_result_error;
        }
        else if (amount == 0)
        {
            break;
        }

        result = urpc_udp_port_write(handle, command + k, &amount);
        if (result != urpc_result_ok)
        {
            if (result == urpc_result_nodevice)
            {
                return urpc_result_nodevice;
            }
            else
            {
                return urpc_udp_port_flush(handle) == urpc_result_nodevice ? urpc_result_nodevice : urpc_result_error;
            }
        }

        if (amount == 0 && k < command_len)
        {
            ZF_LOGD("no more uint8_ts (%d left)... ", (int)(command_len - k));
            return urpc_udp_port_flush(handle) == urpc_result_nodevice ? urpc_result_nodevice : urpc_result_timeout;
        }

        k += amount;
    }

    return urpc_result_ok;
}

static urpc_result_t read_serial_wrapper(urpc_handle_t handle, void *buf, size_t *amount)
{
    while (buffer_size(handle.socket_buffer) < *amount)
    {
        size_t socket_read_size = UDP_PACKAGE_BUFFER_SIZE;
        char package[UDP_PACKAGE_BUFFER_SIZE];
        urpc_result_t res = urpc_read_udp_port(handle, package, &socket_read_size);
        if (res != urpc_result_ok)
        {
            return res;
        }
        buffer_push(handle.socket_buffer, package, socket_read_size);
    }

    buffer_pop(handle.socket_buffer, (char*)(buf), amount);
    return urpc_result_ok;
}

static int command_port_receive(urpc_handle_t handle, uint8_t *response, size_t response_len)
{
    urpc_result_t result;
    size_t amount, k = 0;

    while (k < response_len)
    {
        amount = response_len - k;
        if (response_len < k)
        {
            return urpc_result_error;
        }
        else if (amount == 0)
        {
            break;
        }

        result = read_serial_wrapper(handle, response + k, &amount);
        if (result != urpc_result_ok)
        {
            if (result == urpc_result_timeout)
            {
                return urpc_result_timeout;
            }
            if (result == urpc_result_nodevice)
            {
                return urpc_result_nodevice;
            }
            else
            {
                return urpc_udp_port_flush(handle) == urpc_result_nodevice ? urpc_result_nodevice : urpc_result_error;
            }
        }

        if (amount == 0 && k < response_len)
        {
            ZF_LOGD("no more uint8_ts (%d left)... ", (int)(response_len - k));
            return urpc_udp_port_flush(handle) == urpc_result_nodevice ? urpc_result_nodevice : urpc_result_timeout;
        }

        k += amount;
    }
    ZF_LOGD_MEM(response, response_len, "response ");

    return urpc_result_ok;
}

static int wallclock_diff(time_t sec_beg, int msec_beg, time_t sec_end, int msec_end)
{
    int delta = 0;
    if (sec_end > sec_beg)
    {
        /* be cautious */
        delta = (int) (sec_end - sec_beg);
    }
    delta *= 1000;
    delta += msec_end - msec_beg;
    if (delta < 0)
    {
        delta = 0;
    }
    return delta;
}

static uint16_t get_crc(const uint8_t *pbuf, size_t n)
{
    uint16_t crc, carry_flag, a;
    size_t i, j;
    crc = 0xffff;
    for (i = 0; i < n; i++)
    {
        crc = crc ^ pbuf[i];
        for (j = 0; j < 8; j++)
        {
            a = crc;
            carry_flag = a & 0x0001;
            crc = crc >> 1;
            if (carry_flag == 1)
            {
                crc = crc ^ 0xA001;
            }
        };
    }
    return crc;
}

static int send_synchronization_zeroes(urpc_handle_t handle)
{
    int received = URPC_ZEROSYNC_BURST_SIZE;
    uint8_t zeroes[URPC_ZEROSYNC_BURST_SIZE];
    memset(zeroes, 0, URPC_ZEROSYNC_BURST_SIZE);

    ZF_LOGI("zerosync: sending sync zeroes");


    if (command_port_send(handle, zeroes, URPC_ZEROSYNC_BURST_SIZE) != urpc_result_ok)
    {
        ZF_LOGE("zerosync: command_port_send sync failed");
        return 1;
    }

    while (received > 0)
    {
        if (command_port_receive(handle, zeroes, 1) != urpc_result_ok)
        {
            ZF_LOGE("zerosync: command_port_receive can't get uint8_ts");
            return 1;
        }
        if (zeroes[0] == 0)
        {
            ZF_LOGI("zerosync: got a zero, done");
            return 0;
        }
        --received;
    }

    return 1;
}

static int zerosync(urpc_handle_t handle)
{
    int retry_counter = URPC_ZEROSYNC_RETRY_COUNT;

    ZF_LOGI("zerosync: started");
    while (retry_counter > 0)
    {
        if (send_synchronization_zeroes(handle) == 0)
        {
            ZF_LOGI("zerosync: completed");
            return 0;
        }
        --retry_counter;
    }
    ZF_LOGE("zerosync: synchronization attempts failed, device is lost");
    return 1;
}

static urpc_result_t receive(urpc_handle_t handle, uint8_t *response, size_t len)
{
    urpc_result_t result;
    int delta_time = 0;

    time_t sec_beg, sec_cur, sec_prev;
    int msec_beg, msec_cur, msec_prev;

    urpc_get_wallclock(&sec_beg, &msec_beg);
    sec_prev = sec_beg;
    msec_prev = msec_beg;
    do
    {
        result = command_port_receive(handle, response, len);
        urpc_get_wallclock(&sec_cur, &msec_cur);

        if (result == urpc_result_timeout)
        {
            ZF_LOGI("receive: receive timed out, requesting data from buffer one more time");
            if (wallclock_diff(sec_prev, msec_prev, sec_cur, msec_cur) < URPC_ZEROSYNC_RETRY_DELAY)
            {
                ZF_LOGI("receive: timed out too fast, wait a little");
                urpc_msec_sleep(URPC_ZEROSYNC_RETRY_DELAY);
            }
        }
        else
        {
            return result;
        }

        delta_time = wallclock_diff(sec_beg, msec_beg, sec_cur, msec_cur);
        sec_prev = sec_beg;
        msec_prev = msec_beg;
        ZF_LOGI("receive: passed %d msec, needed at least %d msec", delta_time, URPC_ZEROSYNC_TRIGGER_TIMEOUT);
    } while (delta_time < URPC_ZEROSYNC_TRIGGER_TIMEOUT);

    // All retries
    ZF_LOGE("receive: receive finally timed out");
    if ((result = zerosync(handle)) != 0)
    {
        ZF_LOGE("receive: zerosync failed, nevermind");
    }

    return result;
}


struct urpc_device_udp_t *
urpc_device_udp_create(
    const char *host, int port
)
{
    ZF_LOGD("UDP device host %s port %i", host, port);

    if (port <= 0)
    {
        ZF_LOGE("invalid port %i", port);
        goto validation_failed;
    }

    struct urpc_device_udp_t *device = malloc(sizeof(struct urpc_device_udp_t));
    if (device == NULL)
    {
        goto malloc_failed;
    }

    if (urpc_udp_port_open(host, port, &device->handle) != urpc_result_ok)
    {
        goto udp_port_open_failed;
    }

    device->handle.socket_buffer = malloc(sizeof(buffer_t));
    if (device->handle.socket_buffer == NULL)
    {
        goto buffer_initialization_failed;
    }

    buffer_init(device->handle.socket_buffer);

    return device;

buffer_initialization_failed:
udp_port_open_failed:
    free(device);

validation_failed:
malloc_failed:
    return NULL;
}

urpc_result_t urpc_device_udp_send_request(
    struct urpc_device_udp_t *device,
    const char request_cid[URPC_CID_SIZE],
    const uint8_t *request,
    uint8_t request_len,
    uint8_t *response,
    uint8_t response_len
)
{
    assert(device != NULL);

    urpc_handle_t handle = device->handle;
    if (request_len != 0 && !request)
    {
        ZF_LOGE("can't read from an empty buffer");
    }

    if (response_len != 0 && !response)
    {
        ZF_LOGE("can't write to empty buffer");
    }

    {
        urpc_result_t result;


        // send command
        result = command_port_send(handle, (const uint8_t *)request_cid, URPC_CID_SIZE);
        if (result != urpc_result_ok)
        {
            return result;
        }

        if (request_len != 0)
        {
            result = command_port_send(handle, request, request_len);
            if (result != urpc_result_ok)
            {
                return result;
            }
            uint16_t request_crc = get_crc(request, request_len);
            result = command_port_send(handle, (const uint8_t *)&request_crc, URPC_CRC_SIZE);
            if (result != urpc_result_ok)
            {
                return result;
            }
        }
    }

    {
        urpc_result_t result;
        uint16_t response_crc = 0;
        uint8_t response_cid[URPC_CID_SIZE];

        // read first uint8_t until it's non-zero
        do
        {
            if ((result = receive(handle, response_cid, 1)) != urpc_result_ok)
            {
                return result;
            }
        } while (response_cid[0] == 0);

        // read three uint8_ts
        if ((result = receive(handle, response_cid + 1, 3)) != urpc_result_ok)
        {
            return result;
        }

        // check is it an errv answer
        if (memcmp(errv_cid, response_cid, URPC_CID_SIZE) == 0)
        {
            ZF_LOGW("Response 'errv' received");
            urpc_udp_port_flush(handle);
            return urpc_result_value_error;
        }

        // check is it an errd answer
        if (memcmp(errd_cid, response_cid, URPC_CID_SIZE) == 0)
        {
            ZF_LOGW("Response 'errd' received");
            // flood the controller with zeroes
            zerosync(handle);
            urpc_udp_port_flush(handle);
            return urpc_result_error;
        }

        // check command uint8_ts
        if (memcmp(request_cid, response_cid, URPC_CID_SIZE) != 0)
        {
            // flood the controller with zeroes
            zerosync(handle);
            urpc_udp_port_flush(handle);
            return urpc_result_error;
        }

        if (response_len != 0)
        {
            // receive remaining uint8_ts
            if ((result = receive(handle, response, response_len)) != urpc_result_ok)
            {
                return result;
            }

            if ((result = receive(handle, (uint8_t *) &response_crc, URPC_CRC_SIZE)) != urpc_result_ok)
            {
                return result;
            }
            if (response_crc != get_crc(response, URPC_CRC_SIZE))
            {
                return result;
            }
        }
    }

    return urpc_result_ok;
}

urpc_result_t urpc_device_udp_destroy(
    struct urpc_device_udp_t **device_ptr
)
{
    struct urpc_device_udp_t *device = *device_ptr;
    assert(device != NULL);

    urpc_result_t result = urpc_udp_port_close(device->handle);
    if (result != urpc_result_ok)
    {
        return result;
    }
    
    free(device->handle.socket_buffer);
    device->handle.socket_buffer = NULL;

    free(device);

    *device_ptr = NULL;

    return urpc_result_ok;
}
