#ifndef MAPSERIALURPC_H
#define MAPSERIALURPC_H

#include <map>
#include <mutex>
#include "../urpc.h"
#include "common.hpp"
#include "platform.h"
#include "rw_lock.h"

/*
 * UrpcDevicePHandleGuard - class to contain urpc device handle pointer and its guarding mutex.
 * An Urpc device handle represents some internal resource associated with the urpc device communcation
 */
 

class UrpcDevicePHandleGuard {
public:
    UrpcDevicePHandleGuard() : _uhandle(nullptr), _pmutex(nullptr){ }
    /*
     * Creates urpc device handle pointer, calls urpc device creation function
     */
    static urpc_device_handle_t  create_urpc_h(uint32_t serial, std::mutex *pm); // creates urpc device handle

    /*
     * Executes urpc request operation.
     */
    urpc_result_t urpc_send_request(const char cid[URPC_CID_SIZE],
        const uint8_t *request,
        uint8_t request_len,
        uint8_t *response,
        uint8_t response_len);

    std::mutex *pmutex() const { return _pmutex; }
    urpc_device_handle_t uhandle() const { return _uhandle; }

    /*
     * Destroys urpc device, must be call before destrou_mutex()
     */
    void destroy_urpc_h();
    void destroy_mutex();
    void create_mutex(uint32_t serial); 
    void set_urpc_h(urpc_device_handle_t h) { _uhandle = h; }

    UrpcDevicePHandleGuard(const UrpcDevicePHandleGuard &uh)
    {
        _uhandle = uh.uhandle();
        _pmutex = uh.pmutex();
    }

    UrpcDevicePHandleGuard & operator=(const UrpcDevicePHandleGuard &other)
    {
        _uhandle = other.uhandle();
        _pmutex = other.pmutex();
        return *this;
    }

    static void free_mutex_pool();
private:

    static std::mutex _mutex_pool_mutex;
    static std::map<uint32_t, std::mutex *> _mutex_pool;    
    std::mutex *_pmutex;
    urpc_device_handle_t _uhandle;
};

/*
 * typedef for spying connections pairs
 */
typedef std::pair<conn_id_t, uint32_t>
conn_serial;

/*
 * MapSerialUrpc - class to hold all involved urpc_devices_handle pointers in issue of multithreading.
 * Tcp-connections account is made by using of _conns list : to remove urpc device that could not be addressed;
 */
class MapSerialUrpc : public
    std::map <uint32_t, UrpcDevicePHandleGuard> // map :serial -> UrpcDevicePHandleGuard

{
public:
    MapSerialUrpc(){};
    ~MapSerialUrpc();

    /*
     * Checks if the connection and serial has been already opened.
     * Opens if has not.
     */
    bool open_if_not(conn_id_t conn_id, uint32_t serial);

    /*
     * Executes urpc request operation.
     */
    urpc_result_t operation_urpc_send_request(uint32_t serial,
        const char cid[URPC_CID_SIZE],
        const uint8_t *request,
        uint8_t request_len,
        uint8_t *response,
        uint8_t response_len);

    /*
     * Checks if the urpc device is really opened with this serial
     */
    bool is_opened_and_valid(uint32_t serial);

    /*
     * Removes connection if any, check if any of the rest of active connections matches the given serial,
     * removes urpc device if no connections exist
     * If force_urpc_remove is on, serial must be known and all associated connections will be removed from
     * the this map
     * Choose UINT32_MAX for unknown conn_id or unknown serial, the serial can be evaluated
     * while their connection id is known
     */
    void remove_conn_or_remove_urpc_device(conn_id_t conn_id, uint32_t serial, bool force_urpc_remove = false);
    void log();
    

private:
    ReadWriteLock _rwlock;

     // spy for tcp-connections
    std::list<conn_serial> _conns;
};

#endif
