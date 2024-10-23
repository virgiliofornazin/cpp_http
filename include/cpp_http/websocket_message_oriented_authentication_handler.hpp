#pragma once

#include "impl/config.hpp"

namespace cpp_http
{
    class websocket_message_oriented_authentication_handler
    {
    public:
        virtual ~websocket_message_oriented_authentication_handler() noexcept = default;

        virtual std::string generate_next_authentication_request_message() = 0;
        virtual void handle_next_authentication_response_message(std::string_view const response_message) = 0;
        virtual bool completed() = 0;
        virtual bool authenticated() = 0;

        using shared_ptr = std::shared_ptr<websocket_message_oriented_authentication_handler>;
    };
};
