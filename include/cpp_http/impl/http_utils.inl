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

#include "config.hpp"

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
        static inline auto http_encode_uri_target(std::string client_uri_path, std::string request_uri_path, http_query_string_type const& query_string)
        {
            http_fix_uri_path(client_uri_path);
            http_fix_uri_path(request_uri_path);

            auto prefix = (client_uri_path.empty() && request_uri_path.empty()) ? "/" : "";
            auto encoded_query_string = query_string.to_string();

            return cpp_http_format::format("{}{}{}{}", prefix, client_uri_path, request_uri_path, encoded_query_string);
        }
    }
}
