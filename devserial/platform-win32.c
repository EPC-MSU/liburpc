#include "platform.h"

#include <initguid.h>
// do not force to use DDK with MSVC or other
#ifdef _MSC_VER
    #include <winioctl.h>
#else
    #include <ddk/ntddser.h>
#endif
#include <setupapi.h>
#include <process.h>

#include <zf_log.h>


/*
 * Serial port support
 */

urpc_result_t urpc_serial_port_open(
    const char *path,
    urpc_handle_t *handle
)
{
    HANDLE opened_handle;
    DCB dcb;
    COMMTIMEOUTS ctm;

    opened_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0);
    if (opened_handle == INVALID_HANDLE_VALUE)
    {
        ZF_LOGE("unable to open port %s: ", path);
        return urpc_result_error;
    }

    if (!GetCommState(opened_handle, &dcb))
    {
        if (!CloseHandle(opened_handle))
        {
            ZF_LOGE("error closing port: ");
        }
        ZF_LOGE("can't get comm state due to: ");
        return urpc_result_error;
    }

    dcb.BaudRate = CBR_115200;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    //dcb.fTXContinueOnXoff;
    dcb.fOutX = FALSE;
    dcb.fInX = FALSE;
    dcb.fErrorChar = FALSE;
    dcb.fNull = FALSE;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;
    dcb.fAbortOnError = TRUE;
    dcb.ByteSize = 8;
    dcb.StopBits = 2;

    if (!SetCommState(opened_handle, &dcb))
    {
        if (!CloseHandle( opened_handle ))
        {
            ZF_LOGE("error closing port: ");
        }
        ZF_LOGE("can't set comm state due to: " );
        return urpc_result_error;
    }

    ctm.ReadIntervalTimeout = MAXDWORD;
    ctm.ReadTotalTimeoutConstant = URPC_PORT_TIMEOUT;
    ctm.ReadTotalTimeoutMultiplier = MAXDWORD;
    ctm.WriteTotalTimeoutConstant = 0;
    ctm.WriteTotalTimeoutMultiplier = URPC_PORT_TIMEOUT;

    if (!SetCommTimeouts(opened_handle, &ctm))
    {
        if (!CloseHandle(opened_handle))
        {
            ZF_LOGE("error closing port: ");
        }
        ZF_LOGE("can't get comm state due to: ");
        return urpc_result_error;
    }

    *handle = opened_handle;

    return urpc_result_ok;
}

urpc_result_t urpc_serial_port_close(
    urpc_handle_t handle
)
{
    if (CloseHandle(handle) == -1)
    {
        ZF_LOGE("error closing port: ");
        return urpc_result_error;
    }
    return urpc_result_ok;
}

urpc_result_t urpc_serial_port_flush(
    urpc_handle_t handle
)
{
    if (!PurgeComm(handle, PURGE_RXCLEAR | PURGE_TXCLEAR))
    {
        ZF_LOGE("serial port flush failed: ");
        return urpc_result_error;
    }
    return urpc_result_ok;
}

urpc_result_t urpc_read_serial_port(
    urpc_handle_t handle,
    void *buf,
    size_t *amount
)
{
    DWORD want_to_read = *amount;
    DWORD actually_read;
    if (TRUE != ReadFile(handle, buf, (DWORD)want_to_read, &actually_read, NULL))
    {
        ZF_LOGE("serial port read failed: ");
        return urpc_result_error;
    }
    *amount = actually_read;
    return urpc_result_ok;
}

urpc_result_t urpc_serial_port_write(
    urpc_handle_t handle,
    const void *buf,
    size_t *amount
)
{
    DWORD want_to_write = *amount;
    DWORD actually_written;
    if (TRUE != WriteFile(handle, buf, (DWORD)want_to_write, &actually_written, NULL))
    {
        ZF_LOGE("serial port write failed: ");
        return urpc_result_error;
    }
    *amount = actually_written;
    return urpc_result_ok;
}


/*
 * Misc
 */

void urpc_msec_sleep(
    unsigned int msec
)
{
    Sleep(msec);
}

void urpc_get_wallclock_us(
    uint64_t *us
)
{
    const time_t DELTA_EPOCH_IN_MICROSECS = (time_t)11644473600000000;
    FILETIME ft;
    time_t tmpres = 0;
    if (us != NULL)
    {
        memset(&ft, 0, sizeof(ft));

        GetSystemTimeAsFileTime(&ft);

        tmpres = ft.dwHighDateTime;
        tmpres <<= 32;
        tmpres |= ft.dwLowDateTime;

        /*converting file time to unix epoch*/
        tmpres /= 10;  /*convert into microseconds*/
        tmpres -= DELTA_EPOCH_IN_MICROSECS;
        *us = (time_t)tmpres;
    }
}

void urpc_get_wallclock(
    time_t *sec,
    int *msec
)
{
    uint64_t us;
    urpc_get_wallclock_us(&us);
    *sec = (time_t)(us / 1000000);
    *msec = (us % 1000000) / 1000; // use milliseconds
}
