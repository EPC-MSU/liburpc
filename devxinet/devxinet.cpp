#include "devxinet.h"

#include <cinttypes>
#include <cassert>
#include <map>
#include <exception>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

#include <zf_log.h>

#include "common.hpp"

#include <limits>


#ifdef _MSC_VER
// https://alfps.wordpress.com/2010/06/22/cppx-is-c4099-really-a-sillywarning-disabling-msvc-sillywarnings/
// In standard C++ a forward declaration using struct is equivalent to one using class, there is no difference
// When you define a class there is a difference in the default accessibility of base classes and members, but there’s no difference for a forward declaration.
// The C++98 standard is perhaps not overly clear on this, but it’s clear enough, in §7.1.5.3/3
#pragma warning(disable : 4099)
#endif


#define XINET_BINDY_USER "root-user"
#define XINET_BINDY_KEY {32, 87, 139, 134, 41, 227, 202, 19, 235, 29, 48, 119, 189, 61, 211, 135}
#define DEFAULT_TIMEOUT_TIME 10


class DeviceLost : public std::runtime_error
{
public:
    DeviceLost(const char *message) : std::runtime_error(message) {};
};


class ConnectionLost : public std::runtime_error
{
public:
    ConnectionLost(const char *message) : std::runtime_error(message) {};
};


class ConnectionDuctTape final
{
friend class BindyWrapperSingleton;

private:
    std::mutex mutex;
    bindy::Bindy *bindy;
     // handle "spurious wakeup" problem
    std::condition_variable connection_activity;
    std::vector<uint8_t> last_message;
    const conn_id_t conn_id;
    bool message_really_arrived;
    bool connection_lost;

    explicit ConnectionDuctTape(bindy::Bindy *bindy, conn_id_t conn_id): bindy(bindy), conn_id(conn_id), message_really_arrived(false), connection_lost(false) {};

public:
    std::vector<uint8_t> send_request_and_wait_response(const std::vector<uint8_t> &request)
    {
        ZF_LOGD("sending request to %d...", this->conn_id);
        if(this->connection_lost)
        {
            ZF_LOGE("can't send request to %d due to connection loss!", this->conn_id);
            throw ConnectionLost("");
        }

        std::unique_lock<std::mutex> lock(this->mutex);
        adaptive_wait_send(this->bindy, this->conn_id, request, DEFAULT_TIMEOUT_TIME);
        ZF_LOGD("request has been successfully sent to %d!", this->conn_id);

        ZF_LOGD("waiting for response from %d...", this->conn_id);
        while(!this->message_really_arrived)
        {
            this->connection_activity.wait_for(lock, std::chrono::minutes(1));

            if(this->connection_lost)
            {
                break;
            }
        }
        this->message_really_arrived = false;

        if(this->connection_lost)
        {
            ZF_LOGE("can't receive response from %d due to connection loss!", this->conn_id);
            throw ConnectionLost("");
        }
        else
        {
            ZF_LOGD("response has been successfully received from %d!", this->conn_id);
            return std::move(this->last_message);
        }
    }

    void disconnect()
    {
        ZF_LOGD("performing client-initiated disconnect for %d...", conn_id);
        if(this->connection_lost)
        {
            ZF_LOGD("connection has already been lost for %d!", conn_id);
            return;
        }

        this->bindy->disconnect(this->conn_id);
        std::unique_lock<std::mutex> lock(this->mutex);
        while(!this->connection_lost)
        {
            this->connection_activity.wait(lock);
        }
        ZF_LOGD("client-initiated disconnect for %d has been successfully completed!", conn_id);
    }

    ConnectionDuctTape(const ConnectionDuctTape &other) = delete;
    ConnectionDuctTape(ConnectionDuctTape &&other) = delete;

    ConnectionDuctTape & operator=(const ConnectionDuctTape &other) = delete;
    ConnectionDuctTape & operator=(ConnectionDuctTape &&other) = delete;
};


class BindyWrapperSingleton final {
friend class ConnectionDuctTape;

private:
    bindy::Bindy *bindy;
    std::mutex mutex;
    std::map<conn_id_t, std::weak_ptr<ConnectionDuctTape>> conn_data_by_conn_id;

    static void on_bindy_data_received(bindy::conn_id_t conn_id, std::vector<uint8_t> data)
    {
        ZF_LOGD("data received from %d:", conn_id);

        assert(conn_id != conn_id_invalid);

        if(data.size() < 4)
        {
            ZF_LOGE("message is %zu bytes long - we need the command code at least", data.size());
            return;
        }

        uint32_t protocol_ver;
        read_uint32(&protocol_ver, &data[0]);
        if(protocol_ver != URPC_XINET_PROTOCOL_VERSION)
        {
            ZF_LOGE("%" PRIu32 " protocol is not compatible with this implementation - only %" PRIu32 " protocol is supported", protocol_ver, URPC_XINET_PROTOCOL_VERSION);
            return;
        }

        BindyWrapperSingleton &self = BindyWrapperSingleton::instance();
        std::unique_lock<std::mutex> self_lock(self.mutex);
        try
        {
            auto conn = self.conn_data_by_conn_id.at(conn_id).lock();
            std::unique_lock<std::mutex> conn_lock(conn->mutex);
            conn->last_message = data;
            conn->message_really_arrived = true;
            conn->connection_activity.notify_all();
            /*
             * We have to manually release the mutexes here, because in some cases,
             * after going out of scope, the conn_data destructor is triggered,
             * which also requires these mutexes
             * See #48383 for description
             */
            conn_lock.unlock();
            self_lock.unlock();
        }
        catch(const std::exception &)
        {
            return;
        }

    }

    static void on_bindy_disconnect(conn_id_t conn_id)
    {
        ZF_LOGD("disconnect event received for %d:", conn_id);

        assert(conn_id != conn_id_invalid);
        BindyWrapperSingleton &self = BindyWrapperSingleton::instance();
        std::unique_lock<std::mutex> self_lock(self.mutex);
        try
        {
            if(!self.conn_data_by_conn_id.at(conn_id).expired())
            {
                ZF_LOGD("cleaning up connection for %d", conn_id);
                auto conn = self.conn_data_by_conn_id.at(conn_id).lock();
                std::lock_guard<std::mutex> conn_lock(conn->mutex);
                conn->connection_lost = true;
                conn->connection_activity.notify_all();
            }
            self.conn_data_by_conn_id.erase(conn_id);
        }
        catch(const std::out_of_range &)
        {
            return;
        }
    }

    BindyWrapperSingleton() {
        // we need separate class because static initialization from C++11 only guarantees that
        // if more one thread attempts to start executing the constructor concurrently,
        // only one of them will actually execute it, the rest will wait for the completion of initialization
        bindy::Bindy::initialize_network();
        this->bindy = new bindy::Bindy("", false, false);
        // HACK: we assume that the server has such user as master set - add it to in-memory keyfile
        bindy::user_id_t uid{XINET_BINDY_USER};
        auto key = bindy::aes_key_t{XINET_BINDY_KEY};
        this->bindy->add_user_local(XINET_BINDY_USER, key, uid);

        this->bindy->set_master_local(uid);
        this->bindy->set_handler(&this->on_bindy_data_received);
        this->bindy->set_discnotify(&this->on_bindy_disconnect);
    }

    ~BindyWrapperSingleton() {
        bindy::Bindy::shutdown_network();
    }

    // local static variables initialization in C++11 is threasafe
    // however msvc 2012 doesn't support 'magic statics' so we need explicit static mutex =/
    static std::mutex init_mutex;
public:
    static BindyWrapperSingleton &instance() {
        std::lock_guard<std::mutex> lock(init_mutex);
        static BindyWrapperSingleton *instance;
        if(instance == nullptr)
        {
            instance = new BindyWrapperSingleton();
        }
        return *instance;
    }

    BindyWrapperSingleton(BindyWrapperSingleton const&) = delete;
    BindyWrapperSingleton(BindyWrapperSingleton&&) = delete;
    BindyWrapperSingleton& operator=(BindyWrapperSingleton const&) = delete;
    BindyWrapperSingleton& operator=(BindyWrapperSingleton &&) = delete;

    std::shared_ptr<ConnectionDuctTape> connect(const char *host)
    {
        std::lock_guard<std::mutex> self_lock(this->mutex);
        conn_id_t conn_id = this->bindy->connect(host);
        if(conn_id == conn_id_invalid)
        {
            throw std::runtime_error("");
        }
        auto conn = std::shared_ptr<ConnectionDuctTape>(new ConnectionDuctTape(this->bindy, conn_id), [this, conn_id](ConnectionDuctTape *) {
            this->bindy->disconnect(conn_id);
        });
        this->conn_data_by_conn_id[conn_id] = conn;
        return conn;
    }
};


std::mutex BindyWrapperSingleton::init_mutex;


struct urpc_device_xinet_t {
    std::shared_ptr<ConnectionDuctTape> conn;
    uint32_t serial;

public:
    urpc_device_xinet_t(const char *host, uint32_t serial)
    {
        auto conn = BindyWrapperSingleton::instance().connect(host);

        std::vector<uint8_t> request_buffer(sizeof(urpc_xinet_common_header_t), 0);
        write_uint32(&request_buffer.at(0), URPC_XINET_PROTOCOL_VERSION);
        write_uint32(&request_buffer.at(4), URPC_OPEN_DEVICE_REQUEST_PACKET_TYPE);
        write_uint32(&request_buffer.at(12), serial);

		ZF_LOGD_MEM(request_buffer.data(), (unsigned int)request_buffer.size(), "requesting server to open device with serial %" PRIX32 "... ", serial);
        std::vector<uint8_t> response = conn->send_request_and_wait_response(request_buffer);
        bool opened = response.at(27) != 0;
        if(!opened)
        {
            ZF_LOGE("server failed to open device with serial %" PRIX32 "!", serial);
            throw DeviceLost("");
        }
		ZF_LOGD_MEM(response.data(), (unsigned int)response.size(), "server has successfully opened device with serial %" PRIX32 "!", serial);

        this->conn = conn;
        this->serial = serial;
    };

    urpc_device_xinet_t(const urpc_device_xinet_t &other) = delete;
    urpc_device_xinet_t(urpc_device_xinet_t &&other) = delete;

    urpc_device_xinet_t & operator=(const urpc_device_xinet_t &other) = delete;
    urpc_device_xinet_t & operator=(urpc_device_xinet_t &&other) = delete;

    urpc_result_t send_request(const char request_cid[URPC_CID_SIZE], const uint8_t *request, uint8_t request_len, uint8_t *response, uint8_t response_len)
    {
        std::vector<uint8_t> request_buffer(sizeof(urpc_xinet_common_header_t)+4+URPC_CID_SIZE+request_len, 0);
        write_uint32(&request_buffer.at(0), URPC_XINET_PROTOCOL_VERSION);
        write_uint32(&request_buffer.at(4), URPC_COMMAND_REQUEST_PACKET_TYPE);
        write_uint32(&request_buffer.at(12), this->serial);
        // Pack command id
        std::memcpy(&request_buffer.at(sizeof(urpc_xinet_common_header_t)), request_cid, URPC_CID_SIZE);
        // Pack expected response length
        write_uint32(&request_buffer.at(sizeof(urpc_xinet_common_header_t)+4), response_len);
        // Pack request data
        std::copy(request, request+request_len, request_buffer.begin()+sizeof(urpc_xinet_common_header_t)+4+URPC_CID_SIZE);

		ZF_LOGD_MEM(request_buffer.data(), (unsigned int)request_buffer.size(), "executing request to device with serial %" PRIX32 "... ", serial);
        std::vector<uint8_t> response_buffer = this->conn->send_request_and_wait_response(request_buffer);

        uint32_t response_packet_type;
        read_uint32(&response_packet_type, &response_buffer[4]);
        if(response_packet_type != URPC_COMMAND_RESPONSE_PACKET_TYPE)
        {
            ZF_LOGE("failed to execute request to device with serial %" PRIX32 "... ", serial);
            throw std::runtime_error("");
        }
        urpc_result_t status;
        read_uint32(reinterpret_cast<uint32_t *>(&status), &response_buffer.at(sizeof(urpc_xinet_common_header_t)));
        std::memcpy(response, response_buffer.data()+sizeof(urpc_xinet_common_header_t)+sizeof(uint32_t), response_len);
        if(status != urpc_result_ok)
        {
            ZF_LOGE("failed to execute request to device with serial %" PRIX32 "... ", serial);
            if(status == urpc_result_nodevice)
            {
                throw DeviceLost("");
            }
        }
		ZF_LOGD_MEM(request_buffer.data(), (unsigned int)request_buffer.size(), "request to device with serial %" PRIX32 " has been successfully executed!", serial);
        return (urpc_result_t)status;
    }

    ~urpc_device_xinet_t()
    {
        std::vector<uint8_t> request(sizeof(urpc_xinet_common_header_t), 0);
        write_uint32(&request.at(0), URPC_XINET_PROTOCOL_VERSION);
        write_uint32(&request.at(4), URPC_CLOSE_DEVICE_REQUEST_PACKET_TYPE);
        write_uint32(&request.at(12), this->serial);

        std::vector<uint8_t> response = this->conn->send_request_and_wait_response(request);
        this->conn->disconnect();
    }
};


struct urpc_device_xinet_t * urpc_device_xinet_create(
    const char *host, const char *path
){
    unsigned long serial = strtoul(path, nullptr, 16);

    if(serial > (std::numeric_limits<uint32_t>::max)())
    {
        ZF_LOGE("can't convert path %s to serial number due to uint32 overflow", path);
        return nullptr;
    }

    try
    {
        return new urpc_device_xinet_t(host, static_cast<uint32_t>(serial));
    }
    catch(const std::exception &)
    {
        return nullptr;
    }
}


urpc_result_t urpc_device_xinet_send_request(
    struct urpc_device_xinet_t *device,
    const char request_cid[URPC_CID_SIZE],
    const uint8_t *request,
    uint8_t request_len,
    uint8_t *response,
    uint8_t response_len
)
{
    try
    {
        return device->send_request(request_cid, request, request_len, response, response_len);
    }
    catch(const DeviceLost &)
    {
        return urpc_result_nodevice;
    }
    catch(const std::exception &)
    {
        return urpc_result_error;
    }
}


urpc_result_t urpc_device_xinet_destroy(
    struct urpc_device_xinet_t **device_ptr
)
{
    assert(device_ptr != nullptr);
    urpc_device_xinet_t *device = *device_ptr;
    assert(device != nullptr);
    *device_ptr = nullptr;

    try
    {
        delete device;
        return urpc_result_ok;
    }
    catch(const DeviceLost &)
    {
        return urpc_result_nodevice;
    }
    catch(const std::exception &)
    {
        return urpc_result_error;
    }
}
