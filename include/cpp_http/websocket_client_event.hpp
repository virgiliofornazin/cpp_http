/*
cpp_http library version 1.0.4

Copyright (c) 2024, Virgilio Alexandre Fornazin

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#include "impl/config.hpp"

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

    constexpr static size_t const websocket_client_event_max = static_cast<size_t const>(websocket_client_event::message_received);
    constexpr static size_t const websocket_client_event_count = websocket_client_event_max + 1;

    template <typename websocket_client_event_type>
    static inline void throw_if_websocket_client_event_invalid(websocket_client_event_type const event)
    {
        if (static_cast<size_t>(event) > websocket_client_event_max)
        {
            throw std::out_of_range(cpp_http_format::format("invalid websocket_client_event value: {}", static_cast<size_t>(event)));
        }
    }
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
