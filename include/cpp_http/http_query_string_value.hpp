#pragma once

#include "impl/config.hpp"
#include <stdexcept>

namespace cpp_http
{
	class http_query_string_value
	{
	private:
		std::string _name;
		std::string _value;

	private:
		void check_name()
		{
			if (_name.empty())
			{
				throw std::out_of_range("invalid http query parameter name - empty name");
			}
		}

	public:
		void check_value(std::string_view const& value)
		{
			if (value.empty())
			{
				throw std::out_of_range(cpp_http_format::format("invalid http query_string {} - empty value", _name));
			}
		}
	
	public:
		http_query_string_value() = delete;
		
		http_query_string_value(http_query_string_value const&) = default;
		http_query_string_value(http_query_string_value&&) = default;
		
		http_query_string_value& operator = (http_query_string_value const&) = default;
		http_query_string_value& operator = (http_query_string_value&&) = default;

		explicit http_query_string_value(std::string_view const name)
			: _name(name)
		{
			check_name();
		}

		explicit http_query_string_value(std::string_view const name, std::string_view const value)
			: _name(name), _value(value)
		{
			check_name();
			check_value(value);
		}

		std::string const& name() const noexcept
		{
			return _name;
		}

		std::string const& value() const
		{
			return _value;
		}

		void set_value(std::string_view const value)
		{
			check_value(value);

			_value = value;
		}

		size_t size() const noexcept
		{
			return _value.size();
		}
	};
}
