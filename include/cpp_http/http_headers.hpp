#pragma once

#include "impl/config.hpp"
#include "http_header_values.hpp"
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <iterator>
#include <ostream>

namespace cpp_http
{
	class http_headers
	{
	private:
		std::vector<http_header_values> _header_values;
	
	private:
		auto find(std::string_view const name)
		{
			return std::find_if(std::begin(_header_values), std::end(_header_values), 
				[&name](auto& header_value) { return name == header_value.name(); });
		}
		
		auto find(std::string_view const name) const
		{
			return std::find_if(std::begin(_header_values), std::end(_header_values), 
				[&name](auto& header_value) { return name == header_value.name(); });
		}

	public:
		http_headers() = default;
		
		http_headers(http_headers const&) = default;
		http_headers(http_headers&&) = default;
		
		http_headers& operator = (http_headers const&) = default;
		http_headers& operator = (http_headers&&) = default;

		bool has_value(std::string_view const name) const
		{
			auto iterator = find(name);
			
			return iterator != std::end(_header_values);
		}

		std::string const& value(std::string_view const name) const
		{
			auto iterator = find(name);

			if (iterator != std::end(_header_values))
			{
				auto const& header_values = *iterator;

				return header_values.value();
			}

			throw std::out_of_range(cpp_http_format::format("missing header value {}", name));
		}
		
		http_header_values::values_type const& values(std::string_view const name) const
		{
			auto iterator = find(name);

			if (iterator != std::end(_header_values))
			{
				auto const& header_values = *iterator;

				return header_values.values();
			}

			throw std::out_of_range(cpp_http_format::format("missing header value {}", name));
		}

		void set_value(std::string_view const name, std::string_view const value)
		{
			auto iterator = find(name);

			if (iterator == std::end(_header_values))
			{
				_header_values.emplace_back(name, value);
			}
			else
			{	
				auto& header_values = *iterator;

				header_values.set_value(value);
			}
		}
		
		void set_values(std::string_view const name, std::initializer_list<std::string> values)
		{
			auto iterator = find(name);

			if (iterator == std::end(_header_values))
			{
				_header_values.emplace_back(name, values);
			}
			else
			{				
				auto& header_values = *iterator;

				header_values.set_values(values);
			}
		}
		
		void add_value(std::string_view const name, std::string_view const value)
		{
			auto iterator = find(name);

			if (iterator == std::end(_header_values))
			{
				_header_values.emplace_back(name, value);
			}
			else
			{				
				auto& header_values = *iterator;

				header_values.add_value(value);
			}
		}

		void add_values(std::string_view const name, std::initializer_list<std::string> values)
		{
			auto iterator = find(name);

			if (iterator == std::end(_header_values))
			{
				_header_values.emplace_back(name, values);
			}
			else
			{				
				auto& header_values = *iterator;

				header_values.add_values(values);
			}
		}

		void clear_value(std::string_view const name)
		{
			auto iterator = find(name);

			if (iterator != std::end(_header_values))
			{
				_header_values.erase(iterator);
			}			
		}

		auto begin()
		{
			return std::begin(_header_values);
		}

		auto end()
		{
			return std::end(_header_values);
		}

		auto begin() const
		{
			return std::cbegin(_header_values);
		}

		auto end() const
		{
			return std::cend(_header_values);
		}

		auto cbegin() const
		{
			return std::cbegin(_header_values);
		}

		auto cend() const
		{
			return std::cend(_header_values);
		}

		auto rbegin()
		{
			return std::rbegin(_header_values);
		}

		auto rend()
		{
			return std::rend(_header_values);
		}

		auto rbegin() const
		{
			return std::crbegin(_header_values);
		}

		auto rend() const
		{
			return std::crend(_header_values);
		}

		auto crbegin() const
		{
			return std::crbegin(_header_values);
		}

		auto crend() const
		{
			return std::crend(_header_values);
		}

		size_t size() const noexcept
		{
			return _header_values.size();
		}

		bool empty() const
		{
			return _header_values.empty();
		}

		void clear()
		{
			_header_values.clear();
		}
		
		template <typename char_type, typename traits_type>
		friend inline std::basic_ostream<char_type, traits_type>& operator << (std::basic_ostream<char_type, traits_type>& os, http_headers const& headers)
		{
			for (auto const& header: headers)
			{
				for (auto const& value: header)
				{
					os << header.name() << ": " << value << std::endl;
				}
			}

			return os;
		}
	};
}
