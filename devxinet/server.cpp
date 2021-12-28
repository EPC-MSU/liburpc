#include <cstring>
#include <cstdlib>
#include <cassert>
#include <map>
#include <mutex>
#include <iostream>

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


class Device {
public:
    static Device * create(conn_id_t conn_id, uint32_t serial);

    ~Device();

    conn_id_t conn_id;
    uint32_t serial;
    urpc_device_handle_t handle;
private:
    Device(conn_id_t conn_id, uint32_t serial, urpc_device_handle_t handle);

    Device(const Device & other); // please do not copy Device class, it makes no sense
    Device & operator=(const Device & other); // do not assign it either
};

// All thread-safe locks happen inside Supermap; Device class doesn't know about it
// static
Device * Device::create(conn_id_t conn_id, uint32_t serial) {
    const std::string addr = serial_to_address(serial);
    ZF_LOGI("Open device %s for %u...", addr.c_str(), conn_id);
    urpc_device_handle_t handle = urpc_device_create(addr.c_str());
    if (handle == nullptr) {
        ZF_LOGE("Can\'t open device %s for %u.", addr.c_str(), conn_id);
        return nullptr;
    }

    Device *device = new(std::nothrow) Device(conn_id, serial, handle);
    if (device == nullptr) {
        if (urpc_device_destroy(&handle) != urpc_result_ok) {
            ZF_LOGE("Can not destroy opened device %s for %u.", addr.c_str(), conn_id);
        }
    }

    return device;
}

Device::~Device() {
    // close the device
    urpc_device_destroy(&this->handle);
}

Device::Device(conn_id_t conn_id, uint32_t serial, urpc_device_handle_t handle):
    conn_id(conn_id), serial(serial), handle(handle)
{}


class Supermap {
public:
    Device* findDevice(conn_id_t conn_id, uint32_t serial);
	urpc_device_handle_t findDeviceHandle(conn_id_t conn_id, uint32_t serial);
    bool addDevice(conn_id_t conn_id, uint32_t serial);
    void removeDevice(conn_id_t conn_id, uint32_t serial);
    void removeConnection(conn_id_t conn_id);
	void printfSuperMap();

	tthread::mutex map_mutex;
private:
    std::map<conn_id_t, std::map<uint32_t, Device*> > devices_by_connection;    // connection -> serial -> device ptr
    std::map<uint32_t, std::pair<Device*, int>> devices_by_serial;  // serial -> (device ptr, users)
    //tthread::mutex map_mutex;
};

// для разделения доступа
static tthread::mutex *stdout1_mutex = new tthread::mutex();
// try to print this map
void Supermap::printfSuperMap()
{
	stdout1_mutex->lock();
	printf("Supermap state devices_by_connection\n");
	for (auto m : devices_by_connection)
	{
		printf("  conn_id %u\n", m.first);
		for (auto m1 : m.second)
			printf("       serial %u, Device * conn_id %u, Device * serial %u, Device urpc_handle %u\n", 
			                 m1.first, m1.second -> conn_id, m1.second -> serial, m1.second -> handle);

	}
	printf("Supermap state devices_by_serial\n");
	for (auto m : devices_by_serial)
	{
		printf("  serial %u, Device * conn_id %u, Device * serial %u, Device urpc_handle %u, number of conns: %u\n",
			m.first, m.second.first->conn_id, m.second.first->serial, m.second.first->handle, m.second.second);
	
	}
	stdout1_mutex->unlock();
}

Device* Supermap::findDevice(conn_id_t conn_id, uint32_t serial) {
   std::lock_guard<tthread::mutex> map_lock(map_mutex);

    Device* ptr = nullptr;
    if (devices_by_connection.count(conn_id) > 0 && devices_by_connection.at(conn_id).count(serial) > 0) {
        ptr = devices_by_connection.at(conn_id).at(serial);
    }

    return ptr;
}

urpc_device_handle_t Supermap::findDeviceHandle(conn_id_t conn_id, uint32_t serial) {
	std::lock_guard<tthread::mutex> map_lock(map_mutex);

	//Device* ptr = nullptr;
	if (devices_by_connection.count(conn_id) > 0 && devices_by_connection.at(conn_id).count(serial) > 0) {
	  return devices_by_connection.at(conn_id).at(serial) ->handle;
	}

	return 0;
}


// returns true if addition was successful, or device already exists and available; otherwise returns false
bool Supermap::addDevice(conn_id_t conn_id, uint32_t serial) {
    bool device_opened = false;

    std::lock_guard<tthread::mutex> map_lock(map_mutex);

    if (devices_by_connection[conn_id].count(serial) > 0) {  // Check if device already opened
        ZF_LOGD("Device with serial %lX already opened (for %u).", serial, conn_id);
        device_opened = true;
    } else if (devices_by_serial.count(serial) > 0) {           // Use previously opened by other user shared device
        ZF_LOGD("Use previously opened device with serial %lX (for %u).", serial, conn_id);
        auto &p = devices_by_serial.at(serial);
        ++p.second;
        devices_by_connection.at(conn_id)[serial] = p.first;
        device_opened = true;
    } else {                                           // Open new device
        ZF_LOGD("Open new device with serial %lX for %u...", serial, conn_id);

        try {
            Device *d = Device::create(conn_id, serial);
            if (d != nullptr) {
                devices_by_serial.insert(std::make_pair(serial, std::make_pair(d, 1)));
                devices_by_connection[conn_id][serial] = d;
                device_opened = true;
            }
        } catch (const std::exception &e) {
            ZF_LOGE("Can\'t open device with serial: %u: %s.", serial, e.what());
        }
    }
	ZF_LOGE("Connection is to be done: connection : %u, serial: %u.", conn_id, serial);
    return device_opened;
}

void Supermap::removeDevice(conn_id_t conn_id, uint32_t serial) {
    std::lock_guard<tthread::mutex> map_lock(map_mutex);

    if (devices_by_connection.count(conn_id) > 0) {
        if (devices_by_connection[conn_id].count(serial) > 0) {
            devices_by_connection[conn_id].erase(serial);

            auto &p = devices_by_serial.at(serial);
            if (p.second <= 1) {
                delete p.first;
                devices_by_serial.erase(serial);
            } else {
                --p.second;
            }
        }
    }
}

void Supermap::removeConnection(conn_id_t conn_id) {
	/*
    std::lock_guard<tthread::mutex> map_lock(map_mutex);
	ZF_LOGE("Before Removing connection: %u.", conn_id);
	printfSuperMap();
    if (devices_by_connection.count(conn_id) > 0) {
        for (auto &serial_device_p: devices_by_connection.at(conn_id)) {
            auto &p = devices_by_serial.at(serial_device_p.first);
            if (p.second <= 1) {
                delete p.first;
                devices_by_serial.erase(serial_device_p.first);
            } else {
                --p.second;
            }
        }
		
		ZF_LOGE("Removing connection: %u.", conn_id);
        devices_by_connection.erase(conn_id);
		printfSuperMap();
    }
	*/
}


Supermap supermap;


class CommonDataPacket {
public:
    bool send_data() {
        if (pb == NULL) {
            //ZF_LOGD( "pb == NULL in send_data()" );
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
    ZF_LOGD("From %u received packet of length: %lu.", conn_id, data.size());

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
            ZF_LOGD( "From %u received command request packet.", conn_id );
//			std::lock_guard<tthread::mutex> map_lock(supermap.map_mutex);
            Device * d = supermap.findDevice(conn_id, serial);
			//urpc_device_handle_t u_h = supermap.findDeviceHandle(conn_id, serial);
           if(d == NULL) {
		//if (u_h == NULL) {
//                //ZF_LOGD( "conn_id = " << conn_id << ", serial = " << std::to_string(serial) );
                ZF_LOGE( "Request by %d for raw data to not opened serial, aborting...", conn_id );
                throw std::runtime_error( "Serial not opened" );
            }
            char cid[URPC_CID_SIZE];
            std::memcpy(cid, &data[sizeof(urpc_xinet_common_header_t)], sizeof(cid));

            uint32_t response_len;
            read_uint32(&response_len, &data[sizeof(urpc_xinet_common_header_t) + sizeof(cid)]);

            unsigned long int request_len;
            request_len = data.size() - sizeof(urpc_xinet_common_header_t) - sizeof(cid) - sizeof(response_len);
            std::vector<uint8_t> response(response_len);

            urpc_result_t result = urpc_device_send_request(
                    //u_h, 
					d->handle,
                    cid, 
                    request_len ? &data[sizeof(urpc_xinet_common_header_t) + sizeof(cid) + sizeof(response_len)] : NULL, 
                    request_len,
                    response.data(), 
                    response_len
            );

            DataPacket<URPC_COMMAND_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, d->serial, result, response.data(), response_len);
					//response_packet(conn_id, serial, result, response.data(), response_len);
            if (!response_packet.send_data() || result == urpc_result_nodevice) {
                ZF_LOGE( "To %u command response packet sending error.", conn_id );
			    //supermap.removeConnection(conn_id);
				throw std::exception("Throw to do statndard disconnect!!!");
			
            } else {
                ZF_LOGD( "To %u command response packet sent.", conn_id );
            }
            break;
        }
        case URPC_OPEN_DEVICE_REQUEST_PACKET_TYPE: {
            ZF_LOGD( "From %u received open device request packet.", conn_id );

            DataPacket<URPC_OPEN_DEVICE_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, serial, supermap.addDevice(conn_id, serial));
            if (!response_packet.send_data()) {
                ZF_LOGE( "To %u open device response packet sending error.", conn_id );
		        //supermap.removeConnection(conn_id);
				throw std::exception("Throw to do statndard disconnect!!!");
		    } else {
                ZF_LOGD( "To %u open device response packet sent.", conn_id );
            }
            break;
        }
        case URPC_CLOSE_DEVICE_REQUEST_PACKET_TYPE: {
            ZF_LOGD( "From %u received close device request packet.", conn_id );

            DataPacket<URPC_CLOSE_DEVICE_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, serial);
            response_packet.send_data();
            ZF_LOGD( "To %u close device response packet sent.", conn_id );

            supermap.removeDevice(conn_id, serial);
            break;
        }
        default: {
            ZF_LOGD( "Unknown packet code." );
            break;
        }
    }
}
// ========================================================

void callback_disc(conn_id_t conn_id) {
    supermap.removeConnection(conn_id);
}

void print_help(char *argv[])
{
    std::cout << "Usage: " << argv[0] << " keyfile [{disable_supervisor/enable_supervisor}] [supervisor_limit]"
              << std::endl
              << "Examples: " << std::endl
              << argv[0] << " ~/keyfile.sqlite" << std::endl
              << argv[0] << " ~/keyfile.sqlite enable_supervisor" << std::endl
              << argv[0] << " ~/keyfile.sqlite disable_supervisor" << std::endl
              << argv[0] << " ~/keyfile.sqlite enable_supervisor 30" << std::endl
              << "Supervisor will be enabled by default" << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc < 2) 
    {
        print_help(argv);
        return 0;
    }

    int res = initialization();
    if (res)
    {
        return res;
    }

    bindy::Bindy bindy(argv[1], true, false);
    pb = &bindy;

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

    ZF_LOGI("Starting server...");
    bindy.connect();
    bindy.set_handler(&callback_data);
    bindy.set_discnotify(&callback_disc);

    ZF_LOGI("Server stopped.");
    return 0;
}
