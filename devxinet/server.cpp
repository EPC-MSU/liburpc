#include <cstring>
#include <cstdlib>
#include <cassert>
#include <map>
#include <mutex>
#include <iostream>
#include <algorithm>
#include <functional>

//#define ENABLE_SUPERVISOR

#include <zf_log.h>

#include "../urpc.h"
#include "bindy/bindy.h"
#include "bindy/tinythread.h"
#include "common.hpp"
#include "platform.h"

#ifdef ENABLE_SUPERVISOR
#include "supervisor.hpp"

Supervisor supervisor;
#endif


bindy::Bindy * pb = NULL;


#define SEND_WAIT_TIMEOUT_MS 5000


static bool log_yes = false;

#define ZF_LOGDN(...) \
if (log_yes == true) ZF_LOGD(__VA_ARGS__)

#define ZF_LOGIN(...) \
if (log_yes == true) ZF_LOGI(__VA_ARGS__)



// A write-preference Read-Write lock - taken from https://github.com/bo-yang/read_write_lock
class ReadWriteLock {
public:
	ReadWriteLock() {
		_nread = _nread_waiters = 0;
		_nwrite = _nwrite_waiters = 0;
	}

	void read_lock() {
		std::unique_lock<std::mutex> lck(_mtx);
		if (_nwrite || _nwrite_waiters) {
			_nread_waiters++;
			while (_nwrite || _nwrite_waiters)
				_rcond.wait(lck); // calls lck.unlock() inherently, lck.lock() is called after notified.
			_nread_waiters--;
		}
		_nread++;
	}

	void read_unlock() {
		std::unique_lock<std::mutex> lck(_mtx);
		_nread--;
		if (_nwrite_waiters)
			_wcond.notify_one();
	}

	void write_lock() {
		std::unique_lock<std::mutex> lck(_mtx);
		if (_nread || _nwrite) {
			_nwrite_waiters++;
			while (_nread || _nwrite)
				_wcond.wait(lck);
			_nwrite_waiters--;
		}
		_nwrite++;
	}

	void write_unlock() {
		std::unique_lock<std::mutex> lck(_mtx);
		_nwrite--;
		if (_nwrite_waiters) // write-preference
			_wcond.notify_one();
		else if (_nread_waiters)
			_rcond.notify_all();
	}

private:
	std::mutex _mtx;
	std::condition_variable _rcond;
	std::condition_variable _wcond;
	uint32_t _nread, _nread_waiters;
	uint32_t _nwrite, _nwrite_waiters;
};

// urpc_header - class to encapsulate some urpc device opeartions in issue of multithreading
// instead of Device - small wrapper over urpc_device  api
class urpc_header {
public:
	urpc_header():  _uhandle(nullptr), _pmutex(nullptr){ }
	urpc_header(urpc_device_handle_t purpc);
	static urpc_device_handle_t  create_urpc_h(uint32_t serial);
	std::mutex * pmutex() const { return _pmutex; }
	urpc_device_handle_t uhandle() const { return _uhandle; }
	void destroy_urpc();
	void destroy_mutex();
	
	urpc_header(const urpc_header& uh) 
	{
		_uhandle = uh.uhandle();
		_pmutex = uh.pmutex();
	}

	urpc_header & operator=(const urpc_header & other)
	{
		_uhandle = other.uhandle();
		_pmutex = other.pmutex();
		return *this;
	}

private:
	std::mutex * _pmutex;
	//std::atomic<bool> _valid;
	urpc_device_handle_t _uhandle;
};

urpc_device_handle_t urpc_header::create_urpc_h(uint32_t serial)
{
   const std::string addr = serial_to_address(serial);
   urpc_device_handle_t handle = urpc_device_create(addr.c_str());
   if (handle == nullptr) {
		ZF_LOGE("Can\'t open device %s.", addr.c_str());
	}
   return handle;
}

urpc_header::urpc_header(urpc_device_handle_t purpc):
_uhandle(purpc)
{
   _pmutex = new std::mutex();
}

void urpc_header::destroy_urpc()
{
	std::unique_lock<std::mutex> _lck(*_pmutex);
	if (_uhandle != nullptr) 
	{
		urpc_device_destroy(&_uhandle);
		_uhandle = nullptr;
	}
}

void urpc_header::destroy_mutex()
{
	if (_pmutex != nullptr)
	{
		delete _pmutex;
		_pmutex = nullptr;
	}
}


// for spying connections
typedef std::pair<conn_id_t, uint32_t>
conn_serial;

// instead of Supermap
// MapSerialUrpc -  class to hold all involved urpc_devices in issue of multithreading
// new features:
// don't count tcp-connections any more: let bindy do it
// don't discoonect anyone in case of bad result from urpc except direct command accepted (tcp) to disconnect 
// don't remove urpc device once created
class MapSerialUrpc : public
	 std::map <uint32_t, urpc_header>
	 // map :serial -> urpc_device_class pointer 
{
public:	
	MapSerialUrpc(){};
	~MapSerialUrpc();
	bool open_if_not(conn_id_t conn_id, uint32_t serial);
	urpc_result_t operation_urpc_send_request(uint32_t serial,
		const char cid[URPC_CID_SIZE],
		const uint8_t *request,
		uint8_t request_len,
		uint8_t *response,
		uint8_t response_len);

	bool is_opened_and_valid(uint32_t serial);
	// CHOOSE UINT32_MAx for unknown conn_id or serial
	void decrement_conn_or_remove_urpc_device(conn_id_t conn_id, uint32_t serial, bool force_urpc_remove = false);
	void print_msu();
private:
	ReadWriteLock _rwlock;
	//spy for tcp-connections
	std::list<conn_serial> _conns;
};


MapSerialUrpc msu;

void MapSerialUrpc::print_msu()
{
	_rwlock.read_lock();

	ZF_LOGDN("MapSerialUrpc:");
	for (auto & m : *this)
	{
		ZF_LOGDN("serial_%u -> (urpc ptr %u; mutex ptr %u\n", m.first, m.second.uhandle(), m.second.pmutex());
			                  
	}

	ZF_LOGDN("MapSerialUrpc connections pairs:");
	for (auto & m : _conns)
	{
		ZF_LOGDN("conn_id %u - serial %u\n", m.first, m.second);
	}

	_rwlock.read_unlock();
}

MapSerialUrpc::~MapSerialUrpc()
{
	for (auto m : *this)
	{
		m.second.destroy_urpc();
		m.second.destroy_mutex();
	}
}


static bool _find_conn(const conn_serial & item, conn_id_t conn_id)
{
	return item.first == conn_id;
}

bool _find_serial(const conn_serial & item, uint32_t serial)
{
	return item.second == serial;
}

bool MapSerialUrpc::open_if_not(conn_id_t conn_id, uint32_t serial)
{
	_rwlock.read_lock();
				
	// first, glance, if any is already in list 
	if (std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_conn, std::placeholders::_1, conn_id)) !=
		_conns.cend())
	{
		_rwlock.read_unlock();
		return true;
	}

	urpc_header & uh = (*this)[serial];

	// the device either create OK or  was not created
	if (uh.uhandle() != nullptr) {
      	_rwlock.read_unlock();
		_rwlock.write_lock();
		_conns.insert(_conns.cend(), std::make_pair(conn_id, serial));
		_rwlock.write_unlock();
 		return true;
	}

	// read lock is still on

	// not created, create now
	urpc_device_handle_t purpc = urpc_header::create_urpc_h(serial);
	if (purpc == nullptr) {
		_rwlock.read_unlock();
		return false;
	}
	else
	    _rwlock.read_unlock();

	_rwlock.write_lock();
	if ((*this)[serial].uhandle() == nullptr) // multithreading !!!
	{
		urpc_header real_urpc(purpc);
		(*this)[serial] = real_urpc;
		_conns.insert(_conns.cend(), conn_serial(conn_id, serial));
		//insert(std::make_pair(serial, real_urpc));

	}
	_rwlock.write_unlock();
	return true;
}

bool MapSerialUrpc::is_opened_and_valid(uint32_t serial)
{
	bool ret;
	_rwlock.read_lock();
	urpc_header & uh = (*this)[serial];
	ret = uh.uhandle() != nullptr /*&& uh.is_valid() == true*/ ;
	_rwlock.read_unlock();
	return ret;
}

void MapSerialUrpc::decrement_conn_or_remove_urpc_device(conn_id_t conn_id, uint32_t serial_known, bool force_urpc_remove)
{
	if (conn_id == UINT32_MAX && serial_known == UINT32_MAX)
		return;

	bool destroy_serial = false;
	uint32_t serial = serial_known;

	if (conn_id != UINT32_MAX)   // conn_id is known
	{
		// first,  find and remove_connection
		_rwlock.write_lock();

		std::list<conn_serial>::const_iterator it;
		if ((it = std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_conn, std::placeholders::_1, conn_id))) !=
			_conns.cend())
		{
			if (serial_known == UINT32_MAX)
				serial = it->second;
			_conns.erase(it);
		}
		_rwlock.write_unlock();
	}

	if (serial == UINT32_MAX) return;

	_rwlock.read_lock();
	urpc_header & uh = (*this)[serial];
	if (uh.uhandle() != nullptr)
	{
		if ((force_urpc_remove == true) || 
			std::find_if(_conns.cbegin(), _conns.cend(), std::bind(_find_serial, std::placeholders::_1, serial)) ==
			_conns.cend())

		{
			destroy_serial = true;
			uh.destroy_urpc();
		}
	}
	_rwlock.read_unlock();

	if (!destroy_serial)  return;
	_rwlock.write_lock();
	urpc_header & uh1 = (*this)[serial];
	if (uh1.pmutex() != nullptr && uh1.uhandle() == nullptr)
		uh1.destroy_mutex();
	erase(serial);
	if (conn_id != UINT32_MAX)
	{
		for (auto it = _conns.cbegin(); it != _conns.cend(); it++)
		{
			if (it->first == conn_id)
				_conns.erase(it);

		}
	}
	_rwlock.write_unlock();
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
	urpc_header & uh = (*this)[serial];
	
	if (uh.uhandle() != nullptr)
	{
		std::unique_lock<std::mutex> lck(*uh.pmutex());
		res = urpc_device_send_request(uh.uhandle(), cid, request, request_len, response, response_len);
	}

	_rwlock.read_unlock();

	if (res == urpc_result_nodevice)
	{
		decrement_conn_or_remove_urpc_device(UINT32_MAX, serial, true);
		ZF_LOGE("The urpc device with  serial %u returned urpc_result_nodevice and was closed", serial);
	}
	
	return res;
}

class CommonDataPacket {
public:
    bool send_data() {
        if (pb == NULL) {
            //ZF_LOGDN( "pb == NULL in send_data()" );
            return false;
        }
        try {
            adaptive_wait_send(pb, conn_id, reply, SEND_WAIT_TIMEOUT_MS);
        } catch (const std::exception &) {
            // Logged in adaptive_wait_send()
            return false;
        }
        return true;
    }

protected:
    std::vector<uint8_t> reply;
    conn_id_t conn_id;
};


template <int PacketId>
class DataPacket : public CommonDataPacket { }; // Still allows us to instantiate common packet, which is wrong

template <>
class DataPacket <URPC_OPEN_DEVICE_RESPONSE_PACKET_TYPE> : public CommonDataPacket {
public:
    DataPacket(conn_id_t conn_id, uint32_t serial, bool opened_ok) {
        this->conn_id = conn_id;

        int len = sizeof(urpc_xinet_common_header_t) + sizeof(uint32_t);
        reply.resize(len);
        std::fill(reply.begin(), reply.end(), 0x00);

        write_uint32(&reply.at(0), URPC_XINET_PROTOCOL_VERSION);
        write_uint32(&reply.at(4), URPC_OPEN_DEVICE_RESPONSE_PACKET_TYPE);
        write_uint32(&reply.at(12), serial);
        write_bool(&reply.at(len - 1), opened_ok);
    }
};

template <>
class DataPacket <URPC_CLOSE_DEVICE_RESPONSE_PACKET_TYPE> : public CommonDataPacket {
public:
    DataPacket(conn_id_t conn_id, uint32_t serial) {
        this->conn_id = conn_id;

        int len = sizeof(urpc_xinet_common_header_t) + sizeof(uint32_t);
        reply.resize(len);
        std::fill(reply.begin(), reply.end(), 0x00);

        write_uint32(&reply.at(0), URPC_XINET_PROTOCOL_VERSION);
        write_uint32(&reply.at(4), URPC_CLOSE_DEVICE_RESPONSE_PACKET_TYPE);
        write_uint32(&reply.at(12), serial);
    }
};

template <>
class DataPacket <URPC_COMMAND_RESPONSE_PACKET_TYPE> : public CommonDataPacket {
public:
    DataPacket(conn_id_t conn_id, uint32_t serial, urpc_result_t result, uint8_t* ptr, uint32_t size) {
        this->conn_id = conn_id;

        int len = sizeof(urpc_xinet_common_header_t) + sizeof(result) + size;
        reply.resize(len);
        std::fill (reply.begin(), reply.end(), 0x00);

        write_uint32(&reply.at(0), URPC_XINET_PROTOCOL_VERSION);
        write_uint32(&reply.at(4), URPC_COMMAND_RESPONSE_PACKET_TYPE);
        write_uint32(&reply.at(12), serial);
        write_uint32(&reply.at(sizeof(urpc_xinet_common_header_t)), (uint32_t)result);
        write_bytes(reply.data() + sizeof(urpc_xinet_common_header_t)+sizeof(result), ptr, size);
    }
};

// ========================================================
void callback_data(conn_id_t conn_id, std::vector<uint8_t> data) {
    ZF_LOGDN("From %u received packet of length: %lu.", conn_id, data.size());

    if (data.size() < 16) { // We need at least the protocol version and command code... and serial too
        ZF_LOGE( "From %u received incorrect data packet: Size: %lu, expected at least 16.", conn_id, data.size() );
        throw std::runtime_error( "Incorrect data packet" );
    }

    uint32_t protocol_ver;
    uint32_t command_code;
    uint32_t serial;
    read_uint32(&protocol_ver, &data[0]);
    if(URPC_XINET_PROTOCOL_VERSION != protocol_ver) {
        ZF_LOGE( "From %u received packet with not supported protocol version: %u.", conn_id, protocol_ver );
        return;
    }

    read_uint32(&command_code, &data[4]);
    read_uint32(&serial, &data[12]); // strictly speaking it might read junk in case of enumerate_reply or something else which does not have the serial... if someone sends us such packet

    #ifdef ENABLE_SUPERVISOR
    /*
     * Capture and release (in destructor) serial number
     * if it is captured many times, but never freed, the supervisor will kill this device
     */
    SupervisorLock _s = SupervisorLock(&supervisor, std::to_string(serial));
    #endif

    switch (command_code) {
        case URPC_COMMAND_REQUEST_PACKET_TYPE: {
            ZF_LOGDN( "From %u received command request packet.", conn_id );
            //Device * d = supermap.findDevice(conn_id, serial);
			char cid[URPC_CID_SIZE];
			std::memcpy(cid, &data[sizeof(urpc_xinet_common_header_t)], sizeof(cid));

			uint32_t response_len;
			read_uint32(&response_len, &data[sizeof(urpc_xinet_common_header_t)+sizeof(cid)]);

			unsigned long int request_len;
			request_len = data.size() - sizeof(urpc_xinet_common_header_t)-sizeof(cid)-sizeof(response_len);
			std::vector<uint8_t> response(response_len);

			urpc_result_t result = urpc_result_nodevice;

			if (!msu.is_opened_and_valid(serial))
				ZF_LOGE("Request by %d for raw data to not opened or invalid serial , aborting...", conn_id);
			    //throw std::runtime_error( "Serial not opened or invalid" );
			else
			    result = msu.operation_urpc_send_request(
					//d->handle,
					//d_p.first, 
					serial,
					cid,
					request_len ? &data[sizeof(urpc_xinet_common_header_t)+sizeof(cid)+sizeof(response_len)] : NULL,
					request_len,
					response.data(),
					response_len
					);
			
			DataPacket<URPC_COMMAND_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, /*d->serial*/ serial, result, response.data(), response_len);
			if (!response_packet.send_data() || result == urpc_result_nodevice) {
                ZF_LOGE( "To %u command response not sent.", conn_id );
			 				
            } else {
                ZF_LOGDN( "To %u command response packet sent.", conn_id );
            }
			break;
        }
        case URPC_OPEN_DEVICE_REQUEST_PACKET_TYPE: {
            ZF_LOGDN( "From %u received open device request packet.", conn_id );

            DataPacket<URPC_OPEN_DEVICE_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, serial, //supermap.addDevice(conn_id, serial)
					                                    msu.open_if_not(conn_id, serial));
            if (!response_packet.send_data()) {
                ZF_LOGE( "To %u open device response packet sending error.", conn_id );
		        
		    } else {
                ZF_LOGDN( "To %u open device response packet sent.", conn_id );
            }
			ZF_LOGDN("New connection added conn_id=%u + ...", conn_id);
			msu.print_msu();
            break;
        }
        case URPC_CLOSE_DEVICE_REQUEST_PACKET_TYPE: {
            ZF_LOGDN( "From %u received close device request packet.", conn_id );

            DataPacket<URPC_CLOSE_DEVICE_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, serial);
            response_packet.send_data();
            ZF_LOGDN( "To connection %u close device response packet sent.", conn_id );
			
			//msu.decrement_conn_or_remove_urpc_device(conn_id, serial, false);
            
			//ZF_LOGDN("Connection or Device removed with conn_id=%u + ...", conn_id);
			//msu.print_msu();
			// force socket thread final becouse of this exception
			throw std::runtime_error("Stopping socket_thread");
            break;
        }
        default: {
            ZF_LOGDN( "Unknown packet code." );
            break;
        }
    }
}
// ========================================================

void callback_disc(conn_id_t conn_id) {
    //supermap.removeConnection(conn_id);
	msu.decrement_conn_or_remove_urpc_device(conn_id, UINT32_MAX, false);
	ZF_LOGDN("Connection or Device removed with conn_id=%u + ...", conn_id);
	msu.print_msu();
}

void print_help(char *argv[])
{
    /*
	no supervisor no at all
	std::cout << "Usage: " << argv[0] << " keyfile [{disable_supervisor/enable_supervisor}] [supervisor_limit]"
              << std::endl
              << "Examples: " << std::endl
              << argv[0] << " ~/keyfile.sqlite" << std::endl
              << argv[0] << " ~/keyfile.sqlite enable_supervisor" << std::endl
              << argv[0] << " ~/keyfile.sqlite disable_supervisor" << std::endl
              << argv[0] << " ~/keyfile.sqlite enable_supervisor 30" << std::endl
              << "Supervisor will be enabled by default" << std::endl;
  */

	std::cout << "Usage: " << argv[0] << " keyfile [debug]"
		<< std::endl
		<< "Examples: " << std::endl
		<< argv[0] << " ~/keyfile.sqlite" << std::endl
		<< argv[0] << " ~/keyfile.sqlite debug" << std::endl
		<< "Debug logging will be disabled by default" << std::endl;

}

int main(int argc, char *argv[])
{
    if (argc < 2) 
    {
        print_help(argv);
		std::cin.get();
        return 0;
    }

    int res = initialization();
    if (res)
    {
        return res;
    }

	if (argc > 2)
	{
		if (strcmp(argv[2], "debug") == 0)
		{
			log_yes = true;
		}

	}

    bindy::Bindy bindy(argv[1], true, false, log_yes);
    pb = &bindy;
	
	/* no supervisor at all*/
    #ifdef ENABLE_SUPERVISOR
    if (argc > 2) 
    {
        if (strcmp(argv[2], "disable_supervisor") == 0)
        {
            supervisor.stop();
        }
        else if (strcmp(argv[2], "enable_supervisor") == 0)
        {
          ; // already enabled
        }
        else
        {
            print_help(argv);
            return 0;
        }
    }
    if (argc == 4)
    {
        supervisor.set_limit(std::stoi(argv[3]));
    }
    #endif

    ZF_LOGIN("Starting server...");
    bindy.connect();
    bindy.set_handler(&callback_data);
    bindy.set_discnotify(&callback_disc);

    //ZF_LOGIN("Server stopped.");
    return 0;
}
