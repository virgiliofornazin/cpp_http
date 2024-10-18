#pragma once

#include "impl/config.hpp"
#include "impl/http_utils.inl"
#include "http_query_string_value.hpp"
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <iterator>
#include <ostream>

namespace cpp_http
{
	class http_query_string
	{
	private:
		std::vector<http_query_string_value> _query_string_values;
	
	private:
		auto find(std::string_view const name)
		{
			return std::find_if(std::begin(_query_string_values), std::end(_query_string_values), 
				[&name](auto& query_parameter_value) { return name == query_parameter_value.name(); });
		}
		
		auto find(std::string_view const name) const
		{
			return std::find_if(std::begin(_query_string_values), std::end(_query_string_values), 
				[&name](auto& query_parameter_value) { return name == query_parameter_value.name(); });
		}

	public:
		http_query_string() = default;
		
		http_query_string(http_query_string const&) = default;
		http_query_string(http_query_string&&) = default;
		
		http_query_string& operator = (http_query_string const&) = default;
		http_query_string& operator = (http_query_string&&) = default;

		bool has_value(std::string_view const name) const
		{
			auto iterator = find(name);
			
			return iterator != std::end(_query_string_values);
		}

		std::string const& value(std::string_view const name) const
		{
			auto iterator = find(name);

			if (iterator != std::end(_query_string_values))
			{
				auto const& query_parameter_values = *iterator;

				return query_parameter_values.value();
			}

			throw std::out_of_range(cpp_http_format::format("missing query_parameter value {}", name));
		}
		
		void set_value(std::string_view const name, std::string_view const value)
		{
			auto iterator = find(name);

			if (iterator == std::end(_query_string_values))
			{
				_query_string_values.emplace_back(name, value);
			}
            else
            {	
                auto& query_parameter_values = *iterator;

                query_parameter_values.set_value(value);
            }
		}

		void clear_value(std::string_view const name)
		{
			auto iterator = find(name);

			if (iterator != std::end(_query_string_values))
			{
				_query_string_values.erase(iterator);
			}			
		}

		auto begin()
		{
			return std::begin(_query_string_values);
		}

		auto end()
		{
			return std::end(_query_string_values);
		}

		auto begin() const
		{
			return std::cbegin(_query_string_values);
		}

		auto end() const
		{
			return std::cend(_query_string_values);
		}

		auto cbegin() const
		{
			return std::cbegin(_query_string_values);
		}

		auto cend() const
		{
			return std::cend(_query_string_values);
		}

		auto rbegin()
		{
			return std::rbegin(_query_string_values);
		}

		auto rend()
		{
			return std::rend(_query_string_values);
		}

		auto rbegin() const
		{
			return std::crbegin(_query_string_values);
		}

		auto rend() const
		{
			return std::crend(_query_string_values);
		}

		auto crbegin() const
		{
			return std::crbegin(_query_string_values);
		}

		auto crend() const
		{
			return std::crend(_query_string_values);
		}

		size_t size() const noexcept
		{
			return _query_string_values.size();
		}

		bool empty() const
		{
			return _query_string_values.empty();
		}

		void clear()
		{
			_query_string_values.clear();
		}

		std::string to_string() const
		{
			std::string result;

			char concatenator = '?';

			for (auto const& query_string_value: _query_string_values)
			{
				auto encoded_name = impl::http_uri_encode(query_string_value.name());
				auto encoded_value = impl::http_uri_encode(query_string_value.value());

				result += concatenator;
				result += encoded_name;
				result += '=';
				result += encoded_value;

				concatenator = '&';
			}

			return result;
		}
		
		template <typename char_type, typename traits_type>
		friend inline std::basic_ostream<char_type, traits_type>& operator << (std::basic_ostream<char_type, traits_type>& os, http_query_string const& query_string)
		{
			return os << query_string.to_string();
		}
	};
}
