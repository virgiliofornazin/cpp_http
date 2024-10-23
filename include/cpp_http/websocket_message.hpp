#pragma once

#include "impl/config.hpp"
#include "websocket_message_priority.hpp"

namespace cpp_http
{
    class websocket_message
    {
    private:
        websocket_message_priority _priority = websocket_message_priority::normal;
        cpp_http_timeout_time_point_type _timestamp;
        std::string _body;

    public:
        websocket_message() = default;

        websocket_message(websocket_message const&) = delete;
        websocket_message(websocket_message&&) = default;

        websocket_message& operator = (websocket_message const&) = delete;
        websocket_message& operator = (websocket_message&&) = default;

        explicit websocket_message(websocket_message_priority const priority_, cpp_http_timeout_time_point_type timestamp_, std::string&& body_)
            : _priority(priority_), _timestamp(timestamp_), _body(std::move(body_))
        {
        }

        explicit websocket_message(websocket_message_priority const priority_, std::string&& body_)
            : _priority(priority_), _timestamp(cpp_http_timeout_clock_type::now()), _body(std::move(body_))
        {
        }

        websocket_message_priority priority() const noexcept
        {
            return _priority;
        }

        cpp_http_timeout_time_point_type const& timestamp() const noexcept
        {
            return _timestamp;
        }

        std::string const& body() const noexcept
        {
            return _body;
        }

        void clear()
        {
            _priority = websocket_message_priority::normal;
            _timestamp = {};
            _body.clear();
        }

        std::string& ref()
        {
            return _body;
        }

        std::string&& detach()
        {
            _priority = websocket_message_priority::normal;
            _timestamp = {};
            
            return std::move(_body);
        }

        explicit operator bool() const noexcept
        {
            return _body.empty();
        }

#if __cplusplus >= 2102002L
        auto operator <=> (websocket_message const& other) const noexcept
        {
            return static_cast<unsigned int>(_priority) <=> static_cast<unsigned int>(other._priority);
        }
#else /* __cplusplus >= 2102002L */
        auto operator == (websocket_message const& other) const noexcept
        {
            return static_cast<unsigned int>(_priority) == static_cast<unsigned int>(other._priority);
        }
        
        auto operator != (websocket_message const& other) const noexcept
        {
            return static_cast<unsigned int>(_priority) != static_cast<unsigned int>(other._priority);
        }

        auto operator < (websocket_message const& other) const noexcept
        {
            return static_cast<unsigned int>(_priority) < static_cast<unsigned int>(other._priority);
        }

        auto operator <= (websocket_message const& other) const noexcept
        {
            return static_cast<unsigned int>(_priority) <= static_cast<unsigned int>(other._priority);
        }

        auto operator > (websocket_message const& other) const noexcept
        {
            return static_cast<unsigned int>(_priority) > static_cast<unsigned int>(other._priority);
        }

        auto operator >= (websocket_message const& other) const noexcept
        {
            return static_cast<unsigned int>(_priority) >= static_cast<unsigned int>(other._priority);
        }
#endif /* __cplusplus >= 2102002L */
    };
};