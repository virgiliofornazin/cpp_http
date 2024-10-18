#pragma once

#include "config.hpp"
#include <string_view>
#include <string>

namespace cpp_http
{
	namespace impl
	{
		static inline auto http_uri_encode(std::string_view const value)		
		{
			// TODO: boost.url
			
			char encode_buf[4] = { '%', '\0', '\0', '\0' };
			
			std::string result;

			result.reserve(value.size());

			for (auto const& character: value)
			{
				if (((character >= '0') && (character <= '9')) ||
					((character >= 'a') && (character <= 'z')) ||
					((character >= 'A') && (character <= 'Z')) ||
					(character == 33) ||
					((39 <= character) && (character <= 42)) ||
					((45 <= character) && (character <= 46)) ||
					(character == 95) ||
					(character == 126))
				{
					result += character;
				}
				else
				{
					::sprintf(encode_buf + 1, "%02X", character);
				
					result += encode_buf;
				}
			}

			return result;
		}

		static inline auto http_sni_host_string(bool const is_secure, std::string_view const host, std::string_view const port)
		{
			auto port_string = (port.empty()) || (!is_secure && port == "80") || (is_secure && port == "443")
				? std::string() : cpp_http_format::format(":{}", port);

			return cpp_http_format::format("{}{}", host, port_string);
		}

		static inline void http_fix_uri_path(std::string& path)
		{
			if (path.empty())
			{
				return;
			}

			if (path.at(0) != '/')
			{
				path.insert(path.begin(), '/');
			}

			if (path.at(path.size() - 1) == '/')
			{
				path.resize(path.size() - 1);
			}
		}

		template <typename http_query_string_type>
		static inline auto http_encode_target(std::string client_uri_path, std::string request_uri_path, http_query_string_type const& query_string)
		{
			http_fix_uri_path(client_uri_path);
			http_fix_uri_path(request_uri_path);

			auto prefix = (client_uri_path.empty() && request_uri_path.empty()) ? "/" : "";
			auto encoded_query_string = query_string.to_string();

			return cpp_http_format::format("{}{}{}{}", prefix, client_uri_path, request_uri_path, encoded_query_string);
		}
	}
}
