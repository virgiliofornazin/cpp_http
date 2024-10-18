#pragma once

#include "impl/config.hpp"
#include <ostream>

namespace cpp_http
{
	enum class websocket_event
	{
		connection_error = 0,
		connection_succeeded = 1,
		disconnection = 2,
		send_timed_out = 3,
		receive_timed_out = 4,
		send_error = 7,
		receive_error = 8,
		received_message = 9,
		sent_message = 10
	};
};

namespace std
{
	static inline std::string to_string(cpp_http::websocket_event const event)
	{
		switch (event)
		{
		case cpp_http::websocket_event::connection_error:
			{
				return "connection_error";
			}
		case cpp_http::websocket_event::connection_succeeded:
			{
				return "connection_succeeded";
			}
		case cpp_http::websocket_event::disconnection:
			{
				return "disconnection";
			}
		case cpp_http::websocket_event::send_timed_out:
			{
				return "send_timed_out";
			}
		case cpp_http::websocket_event::receive_timed_out:
			{
				return "receive_timed_out";
			}
		case cpp_http::websocket_event::send_error:
			{
				return "send_error";
			}
		case cpp_http::websocket_event::receive_error:
			{
				return "receive_error";
			}
		case cpp_http::websocket_event::received_message:
			{
				return "received_message";
			}
		case cpp_http::websocket_event::sent_message:
			{
				return "sent_message";
			}
		default:
			{
				return cpp_http_format::format("[invalid websocket_event value {}]", static_cast<size_t>(event));
			}
		}
	}
}
