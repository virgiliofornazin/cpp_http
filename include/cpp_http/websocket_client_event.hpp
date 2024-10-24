#pragma once

#include "impl/config.hpp"
#include <ostream>

namespace cpp_http
{
    enum class websocket_client_event
    {
        connection_error = 0,
        connection_succeeded = 1,
        authentication_error = 2,
        authentication_succeeded = 3,
        disconnection = 4,
        send_timed_out = 5,
        receive_timed_out = 6,
        heartbeat_timed_out = 7,
        send_error = 8,
        receive_error = 9,
        message_sent = 10,
        message_received = 11
    };
};

namespace std
{
    static inline std::string to_string(cpp_http::websocket_client_event const event)
    {
        switch (event)
        {
        case cpp_http::websocket_client_event::connection_error:
            {
                return "connection_error";
            }
        case cpp_http::websocket_client_event::connection_succeeded:
            {
                return "connection_succeeded";
            }
        case cpp_http::websocket_client_event::authentication_error:
            {
                return "authentication_error";
            }
        case cpp_http::websocket_client_event::authentication_succeeded:
            {
                return "authentication_succeeded";
            }
        case cpp_http::websocket_client_event::disconnection:
            {
                return "disconnection";
            }
        case cpp_http::websocket_client_event::send_timed_out:
            {
                return "send_timed_out";
            }
        case cpp_http::websocket_client_event::receive_timed_out:
            {
                return "receive_timed_out";
            }
        case cpp_http::websocket_client_event::heartbeat_timed_out:
            {
                return "heartbeat_timed_out";
            }
        case cpp_http::websocket_client_event::send_error:
            {
                return "send_error";
            }
        case cpp_http::websocket_client_event::receive_error:
            {
                return "receive_error";
            }
        case cpp_http::websocket_client_event::message_sent:
            {
                return "message_sent";
            }
        case cpp_http::websocket_client_event::message_received:
            {
                return "message_received";
            }
        default:
            {
                return cpp_http_format::format("[invalid websocket_client_event value {}]", static_cast<size_t>(event));
            }
        }
    }
}
