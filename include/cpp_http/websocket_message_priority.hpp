#pragma once

#include "impl/config.hpp"
#include <ostream>

namespace cpp_http
{
    enum class websocket_message_priority
    {
        lowest = 0,
        low = 1,
        normal = 2,
        high = 3,
        highest = 4
    };

    constexpr static size_t const websocket_message_priority_max = static_cast<size_t const>(websocket_message_priority::highest);
    constexpr static size_t const websocket_message_priority_count = websocket_message_priority_max + 1;
};

namespace std
{
    static inline std::string to_string(cpp_http::websocket_message_priority const event)
    {
        switch (event)
        {
        case cpp_http::websocket_message_priority::lowest:
            {
                return "lowest";
            }
        case cpp_http::websocket_message_priority::low:
            {
                return "low";
            }
        case cpp_http::websocket_message_priority::normal:
            {
                return "normal";
            }
        case cpp_http::websocket_message_priority::high:
            {
                return "high";
            }
        case cpp_http::websocket_message_priority::highest:
            {
                return "highest";
            }
        default:
            {
                return cpp_http_format::format("[invalid websocket_message_priority value {}]", static_cast<size_t>(event));
            }
        }
    }
}
