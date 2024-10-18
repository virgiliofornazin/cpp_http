#pragma once

#include "impl/config.hpp"
#include "http_method.hpp"
#include "http_headers.hpp"
#include <boost/json.hpp>
#include <ostream>
#include <sstream>

namespace cpp_http
{
	class http_response
	{
	private:
		uint16_t _code = 0;
		http_headers _headers;
		std::string _body;

	public:
		http_response() = default;
		
		http_response(http_response const&) = default;
		http_response(http_response&&) = default;
		
		http_response& operator = (http_response const&) = default;
		http_response& operator = (http_response&&) = default;
		
		bool succeeded() const
		{
			return ((_code > 199) && (_code < 300));
		}

		uint16_t code() const noexcept
		{
			return _code;
		}

		void set_code(uint16_t const code)
		{
			_code = code;
		}

		http_headers& headers() noexcept
		{
			return _headers;
		}
		
		http_headers const& headers() const noexcept
		{
			return _headers;
		}
		
		void set_body(std::string const& body)
		{
			_body = body;
		}
		
		std::string const& body() const noexcept
		{
			return _body;
		}
		
		boost::json::value json_body() const
		{
			return boost::json::parse(_body);
		}

		void clear()
		{
			_code = 0;
			_headers.clear();
			_body.clear();
		}

		using shared_ptr = std::shared_ptr<http_response>;
		
		shared_ptr clone()
		{
			return std::make_shared<http_response>(*this);
		}

		std::string to_string() const
		{
			std::stringstream ss;

			ss  << "HTTP RESPONSE CODE "
				<< _code
				<< std::endl
				<< _headers
				<< std::endl
				<< _body;

			return ss.str();
		}

		template <typename char_type, typename traits_type>
		friend inline std::basic_ostream<char_type, traits_type>& operator << (std::basic_ostream<char_type, traits_type>& os, http_response const& response)
		{
			return os << response.to_string();
		}
	};
}

namespace std
{
	static inline std::string to_string(cpp_http::http_response const& response)
	{
		return response.to_string();
	}
}
