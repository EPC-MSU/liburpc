#include <cstring>
#include <cstdlib>
#include <cassert>
#include <iostream>
#include <algorithm>
#include <functional>
#include <zf_log.h>
#include "mapserialurpc.h"

std::map<uint32_t, std::mutex *> UrpcDevicePHandleGuard::_mutex_pool;
std::mutex UrpcDevicePHandleGuard::_mutex_pool_mutex;

urpc_device_handle_t UrpcDevicePHandleGuard::create_urpc_h(uint32_t serial, std::mutex *pm)
{
	const std::string addr = serial_to_address(serial);
    std::unique_lock<std::mutex> _lck(*pm);
    urpc_device_handle_t handle = urpc_device_create(addr.c_str());
    if (handle == nullptr) 
    {
        ZF_LOGE("Can\'t open device %s.", addr.c_str());
    }
    else
    {
        ZF_LOGD("Just opened device %u.", serial);
    }
    return handle;
}

/*
 * Executes urpc request operation.
 */
urpc_result_t UrpcDevicePHandleGuard::urpc_send_request(const char cid[URPC_CID_SIZE],
    const uint8_t *request,
    uint8_t request_len,
    uint8_t *response,
    uint8_t response_len)
{
    std::unique_lock<std::mutex> lck(*pmutex());
	if (_uhandle != nullptr)
	{

        ZF_LOGD("In sending request to handle %u...", _uhandle);
        urpc_result_t result = urpc_device_send_request(_uhandle, cid, request, request_len, response, response_len);
        ZF_LOGD("urpc_device_send_request for handle %u returned %d.", _uhandle, result);
        return result;
    }
    return urpc_result_nodevice;
}

void UrpcDevicePHandleGuard::destroy_urpc_h()
{
	std::unique_lock<std::mutex> _lck(*_pmutex);
    if (_uhandle != nullptr)
    {
       ZF_LOGD("Urpc device handle at destroing %u.", _uhandle);
       urpc_device_destroy(&_uhandle);
       ZF_LOGD("Urpc device handle at destroyed %u.", _uhandle);
       _uhandle = nullptr;
    }
}

void UrpcDevicePHandleGuard::create_mutex(uint32_t serial)
{
    std::unique_lock<std::mutex> _lck(_mutex_pool_mutex);
    if (_mutex_pool.find(serial) == _mutex_pool.cend())
    {
        _mutex_pool[serial] = new std::mutex();
    }
    _pmutex =  _mutex_pool[serial];
}

void UrpcDevicePHandleGuard::free_mutex_pool()
{
    // some strange iterator behavior when it's container is empty
    if (_mutex_pool.size() == 0) return;
    std::map<uint32_t, std::mutex *>::const_iterator mpli = _mutex_pool.cbegin();
 
    for (; mpli != _mutex_pool.cend(); mpli++)
    {
        delete mpli -> second;
    } 
}

void UrpcDevicePHandleGuard::destroy_mutex()
{
  _pmutex -> try_lock();
  _pmutex -> unlock();   
  // anyway, pmutex will be unlocked definitly
  // _pmutex points to some once allocated object, do not need to be deallocated every time at the end of using
  _pmutex = nullptr;
}

void MapSerialUrpc::_log()
{
    //_rwlock.read_lock();

    ZF_LOGD("MapSerialUrpc:");
    for (auto &m : *this)
    {
        ZF_LOGD("serial_%u -> (urpc ptr %u; mutex ptr %u\n", m.first, m.second.uhandle(), m.second.pmutex());
    }

    ZF_LOGD("MapSerialUrpc connections pairs:");
    for (auto &m : _conns)
    {
        ZF_LOGD("conn_id %u - serial %u\n", m.first, m.second);
    }

    //_rwlock.read_unlock();
}

MapSerialUrpc::~MapSerialUrpc()
{
    // some strange iterator behavior when it's container is empty
    if (size() != 0)
    {

        for (auto m : *this)
        {
            ZF_LOGD("Close device at deinit stage %u.", m.first);
            m.second.destroy_urpc_h();
            m.second.destroy_mutex();
        }
    }

   UrpcDevicePHandleGuard::free_mutex_pool();
}

static bool _find_conn(const conn_serial &item, conn_id_t conn_id)
{
    return item.first == conn_id;
}

static bool _find_serial(const conn_serial &item, uint32_t serial)
{
    return item.second == serial;
}

bool MapSerialUrpc::open_if_not(conn_id_t conn_id, uint32_t serial)
{
    _rwlock.write_lock();

    // first, glance, if any is already in list
    if (std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_conn, std::placeholders::_1, conn_id)) !=
        _conns.cend())
    {
        _rwlock.write_unlock();
        return true;
    }
   
    /*
    * already, first, create connection 
    */
     _conns.insert(_conns.cend(), std::make_pair(conn_id, serial));
	 ZF_LOGD("Add connection %u", conn_id);
	 _log();

     MapSerialUrpc::iterator map_it = find(serial);
	    /*
     * pmutex must be created first and guard creation also
     */
     if (find(serial) == cend())
     {
        (*this)[serial].create_mutex(serial); // new map element also created and inserte
     }
     _rwlock.write_unlock();
     _rwlock.read_lock();
     UrpcDevicePHandleGuard &uh = (*this)[serial];
	 if (uh.pmutex() != nullptr) // check if someone else already created this
     {
   		if (uh.uhandle() != nullptr && !uh.is_destroy_flag())
		{
			_rwlock.read_unlock();
			return true;
		}
		//
		_rwlock.read_unlock();
		urpc_device_handle_t purpc = UrpcDevicePHandleGuard::create_urpc_h(serial, uh.pmutex());
        _rwlock.write_lock();                              // multithreding !!!
		if (purpc != nullptr)
		{
				(*this)[serial].set_urpc_h(purpc);
				(*this)[serial].create_mutex(serial);  // could be recreating
		}
	     
        if ((*this)[serial].uhandle() == nullptr)
        {
			_erase_connection_pair(conn_id);
            //(*this)[serial].destroy_mutex();
            erase(serial);
        }
        _rwlock.write_unlock();
        return purpc != nullptr;
    
    }
    else
    {
        _rwlock.read_unlock();
        return uh.uhandle() != nullptr;
    }
}

void MapSerialUrpc::_erase_connection_pair(conn_id_t conn_id)
{
	if (conn_id != UINT32_MAX)
	{
		std::list<conn_serial>::const_iterator it;
		if ((it = std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_conn, std::placeholders::_1, conn_id))) !=
			_conns.cend())
			_conns.erase(it);
	}
}

uint32_t MapSerialUrpc::_count_conns_serial(uint32_t serial)
{
	uint32_t count = 0;
    for (auto it = _conns.cbegin(); it != _conns.cend(); it++)
	{
		if (it -> second == serial)
			count++;
	}
	ZF_LOGD("Count of _conns to serial %u = %u", serial, count);
	return count;
}

void MapSerialUrpc::remove_conn_or_remove_urpc_device(conn_id_t conn_id, uint32_t serial_known, bool force_urpc_remove)
{
    if (conn_id == UINT32_MAX)
        return;
    // first check if connection exists (non-deleted earlier) in case of unknown serial (call from catch-block,
    // to minimize catch-block actions) 
    if (serial_known == UINT32_MAX && conn_id != UINT32_MAX)
    {
        bool exit_ok;
        _rwlock.read_lock();
        exit_ok = (std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_conn, std::placeholders::_1, conn_id)) ==
                  _conns.cend());
        _rwlock.read_unlock();
        if (exit_ok) return;     // already removed - lets go out
    }

    bool destroy_serial = false;
    uint32_t serial = serial_known;

    // first, find serial
	_rwlock.read_lock();

    std::list<conn_serial>::const_iterator it;
    // find the conn_id connection in _conns list of pairs 
    if ((it = std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_conn, std::placeholders::_1, conn_id))) !=
            _conns.cend())
    {
            if (serial_known == UINT32_MAX)
                serial = it->second;
    }
	
	_rwlock.read_unlock();

	if (serial == UINT32_MAX)
	{
		return;
	}
    _rwlock.write_lock();
	_erase_connection_pair(conn_id);
	_rwlock.write_unlock();
	
	
	_rwlock.read_lock();
	if (find(serial) == cend())
	{
		_rwlock.read_unlock();
		return;
	}
	
    UrpcDevicePHandleGuard &uh = (*this)[serial];
	if ((force_urpc_remove == true) ||
		//check if there is any device with this serial in the the _conns list of pairs
		std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_serial, std::placeholders::_1, serial)) ==
		_conns.cend())
	{
		uh.set_destroy_flag();
		_rwlock.read_unlock();
		uh.destroy_urpc_h();
		_rwlock.write_lock();
		if (uh.uhandle() == nullptr)
		{
			//uh.destroy_mutex();
			erase(serial);
			ZF_LOGD("Serial has been destroyed: conn_id - %u serial - %u", conn_id, serial);
		}
		else
			ZF_LOGD("Serial has NOT been destroyed: conn_id - %u serial - %u", conn_id, serial);
		_log();
		_rwlock.write_unlock();
	}
	else
		_rwlock.read_unlock();
	
}

urpc_result_t MapSerialUrpc::operation_urpc_send_request(uint32_t serial,
    const char cid[URPC_CID_SIZE],
    const uint8_t *request,
    uint8_t request_len,
    uint8_t *response,
    uint8_t response_len)
{
    urpc_result_t res = urpc_result_nodevice;
    _rwlock.read_lock();
    if (find(serial) != cend())
    {
        _rwlock.read_unlock();
        res = (*this)[serial].urpc_send_request(cid, request, request_len, response, response_len);

        if (res == urpc_result_nodevice)
        {
            remove_conn_or_remove_urpc_device(UINT32_MAX, serial, true);
            ZF_LOGE("The urpc device with  serial %u returned urpc_result_nodevice and was closed", serial);
        }
    }
    else
    {
        _rwlock.read_unlock();
    }
    return res;
}

