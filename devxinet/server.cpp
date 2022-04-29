#include <cstring>
#include <cstdlib>
#include <cassert>
#include <map>
#include <mutex>
#include <iostream>
#include <algorithm>
#include <functional>
#include <ctype.h>

#if not defined(WIN32) && not defined(WIN64)
  #include <execinfo.h>
  #include <signal.h>
#endif

/*
 * Supervisor option.
 * It may not work properly on windows now.
 */
// #define ENABLE_SUPERVISOR

#include <zf_log.h>

#include "../urpc.h"
#include "bindy/bindy.h"
#include "bindy/tinythread.h"
#include "common.hpp"
#include "platform.h"
#include "mapserialurpc.h"

#ifdef ENABLE_SUPERVISOR
#include "supervisor.hpp"

Supervisor supervisor;
#endif


bindy::Bindy * pb = NULL;


#define SEND_WAIT_TIMEOUT_MS 5000

MapSerialUrpc msu;

class CommonDataPacket {
public:
    bool send_data() {
        if (pb == NULL) {
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
    DataPacket(conn_id_t conn_id, uint32_t serial, urpc_result_t result, uint8_t *ptr, uint32_t size) {
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

    bool added;
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

            char cid[URPC_CID_SIZE];
            std::memcpy(cid, &data[sizeof(urpc_xinet_common_header_t)], sizeof(cid));

            uint32_t response_len;
            read_uint32(&response_len, &data[sizeof(urpc_xinet_common_header_t) + sizeof(cid)]);

            unsigned long int request_len;
            request_len = data.size() - sizeof(urpc_xinet_common_header_t) - sizeof(cid) - sizeof(response_len);
            std::vector<uint8_t> response(response_len);

            urpc_result_t result = msu.operation_urpc_send_request(
                    serial,
                    cid,
                    request_len ? &data[sizeof(urpc_xinet_common_header_t) + sizeof(cid) + sizeof(response_len)] : NULL,
                    request_len,
                    response.data(),
                    response_len
                );
                      
            DataPacket<URPC_COMMAND_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, serial, result, response.data(), response_len);
            if (result == urpc_result_nodevice)
                ZF_LOGE("The operation_urpc_send_reqest returned urpc_result_nodevic (conn_id = %u).", conn_id);
            if (!response_packet.send_data())               
                ZF_LOGD("To %u command response packet send failed.", conn_id);
            break;
        }

        case URPC_OPEN_DEVICE_REQUEST_PACKET_TYPE: {
            ZF_LOGD( "From %u received open device request packet.", conn_id );
            added = msu.open_if_not(conn_id, serial);
            DataPacket<URPC_OPEN_DEVICE_RESPONSE_PACKET_TYPE> response_packet(conn_id, serial, added);

            if (!response_packet.send_data()) {
                ZF_LOGE("To %u open device response packet sending error.", conn_id);
            } else {
                ZF_LOGD("To %u open device response packet sent.", conn_id);
            }

            if (added)
            {
                ZF_LOGD("New connection added conn_id=%u + ...", conn_id);
            }
            msu.log();
            break;
        }
        case URPC_CLOSE_DEVICE_REQUEST_PACKET_TYPE: {
            ZF_LOGD( "From %u received close device request packet.", conn_id );
            msu.remove_conn_or_remove_urpc_device(conn_id, UINT32_MAX, false);
            ZF_LOGD("Connection or Device removed ordinary with conn_id=%u + ...", conn_id);
            msu.log();
            DataPacket<URPC_CLOSE_DEVICE_RESPONSE_PACKET_TYPE>
                    response_packet(conn_id, serial);
            response_packet.send_data();
            ZF_LOGD( "To connection %u close device response packet sent.", conn_id);

            /*!!! to delete this comments */
            // We don’t try to close the device here.
            // It will be closed in the callback_disc() function after the thread termination.
            // Force socket thread final becouse of this exception.
            //throw std::runtime_error("Stopping socket_thread");
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
    msu.remove_conn_or_remove_urpc_device(conn_id, UINT32_MAX, false);
    ZF_LOGD("Attempt to remove connection or device in catch block with conn_id=%u + ...", conn_id);
    msu.log();
}

void print_help(char *argv[], bool print_err)
{
	if (print_err)
		std::cout << "ERROR: no valid sqlite key file provided" << std::endl;
#if ZF_LOG_LEVEL <= ZF_LOG_DEBUG
    std::cout << 
        "Usage: " << argv[0] << " keyfile [debug]"
        << std::endl
        << "Examples: " << std::endl
        << argv[0] << " ~/keyfile.sqlite" << std::endl
        << argv[0] << " ~/keyfile.sqlite debug" << std::endl
        << "Debug logging will be disabled by default" << std::endl;
#else
	std::cout << "Usage: " << argv[0] << " keyfile"
		<< std::endl
		<< "Examples: " << std::endl
		<< argv[0] << " ~/keyfile.sqlite" << std::endl;
#endif
}

#if not defined(WIN32) && not defined(WIN64)
void handler(int sig) {
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 32);

  // print out all the frames to stderr
  ZF_LOGE("IN SIGNAL HANDLER: signal no %d:\n", sig);
  ZF_LOGE("Stack trace...");
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  ZF_LOGE("End of stack trace.");
  exit(1);
}

//the next function id not C standard, not supported in non win, the next is manual definition  
char *strlwr(char *str)
{
    unsigned char *p = (unsigned char *)str;

    while (*p) {
        *p = tolower((unsigned char)*p);
        p++;
    }

    return str;
}
#endif

ZF_LOG_DEFINE_GLOBAL_OUTPUT_LEVEL;



int main(int argc, char *argv[])
{
    
#if not defined(WIN32) && not defined(WIN64)
    signal(SIGSEGV, handler);   // install our handler  
#endif
    std::cout << "=== uRPC XiNet Server "
              << URPC_XINET_VERSION_MAJOR << "."
              << URPC_XINET_VERSION_MINOR << "."
              << URPC_XINET_VERSION_BUGFIX << " "
              << "===" << std::endl;

    // if params count is not enough or there is just one param - debug
    // server can not start
	if (argc < 3)
    {
		bool exit = true;
		if (argc == 2)
		{
			char *s = argv[1];
            strlwr(s);
			if (strcmp(s, "-help") != 0 && strcmp(s, "help") != 0
				&& strcmp(s, "--help") != 0 && strcmp(s, "-h") != 0
				&& strcmp(s, "--h") != 0)
				exit = false;
		}
		if (exit)
		{
			print_help(argv, argc < 2);
			std::cin.get(); // To avoid console closing
			return 0;
		}
    }

    int res = initialization();
    if (res)
    {
        return res;
    }

    zf_log_set_output_level(ZF_LOG_WARN);

    if (argc > 2)
    {
        strlwr(argv[2]);
        if (strcmp(argv[2], "debug") == 0)
        {
            zf_log_set_output_level(ZF_LOG_DEBUG);
        }
    }
    
    try
    {
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
    } 
    catch (std::exception &ex)
    {
        std::cout << "Exception catched: " << ex.what() << std::endl
                  << "Server stopped" << std::endl;
    }
    return 0;
}
