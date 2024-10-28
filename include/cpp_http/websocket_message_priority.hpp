/*
cpp_http library version 1.0.3

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
    enum class websocket_message_priority
    {
        highest = 0,
        high = 1,
        normal = 2,
        low = 3,
        lowest = 4
    };

    constexpr static size_t const websocket_message_priority_max = static_cast<size_t const>(websocket_message_priority::lowest);
    constexpr static size_t const websocket_message_priority_count = websocket_message_priority_max + 1;

    template <typename websocket_message_priority_type>
    static inline void throw_if_websocket_message_priority_invalid(websocket_message_priority_type const priority)
    {
        if (static_cast<size_t>(priority) > websocket_message_priority_max)
        {
            throw std::out_of_range(cpp_http_format::format("invalid websocket_message_priority value: {}", static_cast<size_t>(priority)));
        }
    }
};

namespace std
{
    static inline std::string to_string(cpp_http::websocket_message_priority const event)
    {
        switch (event)
        {
        case cpp_http::websocket_message_priority::highest:
            {
                return "highest";
            }
        case cpp_http::websocket_message_priority::high:
            {
                return "high";
            }
        case cpp_http::websocket_message_priority::normal:
            {
                return "normal";
            }
        case cpp_http::websocket_message_priority::low:
            {
                return "low";
            }
        case cpp_http::websocket_message_priority::lowest:
            {
                return "lowest";
            }
        default:
            {
                return cpp_http_format::format("[invalid websocket_message_priority value {}]", static_cast<size_t>(event));
            }
        }
    }
}
