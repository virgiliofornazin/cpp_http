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
#include "http_utils.inl"
#include "ssl_utils.inl"
#include "../http_method.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace cpp_http
{
    namespace impl
    {
        static inline void http_update_uri(bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string& uri_path, std::string& uri, std::string& uri_port_resolve)
        {
            auto port_string = (uri_port.empty()) || (!uri_protocol_is_secure && (uri_port == "80" || uri_port == "http")) || (uri_protocol_is_secure && (uri_port == "443" || uri_port == "https"))
                ? std::string() : cpp_http_format::format(":{}", uri_port);

            uri_port_resolve = uri_port.empty() ? (uri_protocol_is_secure ? "443" : "80") : uri_port;

            http_fix_uri_path(uri_path);

            uri = cpp_http_format::format("{}{}://{}{}{}", uri_protocol, (uri_protocol_is_secure ? "s" : ""), uri_host, port_string, uri_path);
        }

        template <typename boost_beast_response_type, typename http_headers_type>
        static inline void to_http_request_headers(http_headers_type& headers, boost_beast_response_type const& beast_response)
        {
            for (auto const& header: beast_response.base())
            {
                auto const& name = header.name_string();
                auto const& value = header.value();

                headers.add_value(name, value);
            }
        }

        template <typename boost_beast_request_type, typename http_headers_type>
        static inline void to_beast_http_request_headers(boost_beast_request_type& beast_request, http_headers_type const& headers)
        {
            /* TODO multiple values per same header ID in boost::beast... */
            
            for (auto const& header: headers)
            {
                auto const& name = header.name();
                auto const& value = header.value();

                beast_request.set(name, value);
            }
        }

        static inline auto to_beast_http_request_verb(http_method const method)
        {
            switch (method)
            {
            case http_method::get:
                {
                    return boost::beast::http::verb::get;
                }
            case http_method::post:
                {
                    return boost::beast::http::verb::post;
                }
            case http_method::put:
                {
                    return boost::beast::http::verb::put;
                }
            case http_method::delete_:
                {
                    return boost::beast::http::verb::delete_;
                }
            case http_method::patch:
                {
                    return boost::beast::http::verb::patch;
                }
            case http_method::head:
                {
                    return boost::beast::http::verb::head;
                }
            case http_method::options:
                {
                    return boost::beast::http::verb::options;
                }
            default:
                {
                    throw std::out_of_range(cpp_http_format::format("[invalid http_method value {}]", static_cast<size_t>(method)));
                }
            }
        }

        template <typename boost_beast_request_type, typename http_request_type, typename http_client_type>
        static inline std::string to_beast_http_request(boost_beast_request_type& beast_request, http_request_type& request, http_client_type& client)
        {
            auto protocol_version = 11;
            auto verb = to_beast_http_request_verb(request.method());
            auto target = http_encode_uri_target(client.uri_path(), request.uri_path(), request.query_string());
            auto host_string = ssl_sni_host_string(client.uri_protocol_is_secure(), client.uri_host(), client.uri_port());

            request.headers().set_value("Host", host_string);

            if (request.headers().has_value("User-Agent"))
            {
                request.headers().set_value("User-Agent", client.user_agent());
            }

            if (request.headers().has_value("Accept"))
            {
                request.headers().set_value("Accept", "*/*");
            }

            beast_request = std::move(boost_beast_request_type(verb, target, protocol_version));
            
            to_beast_http_request_headers(beast_request, request.headers());

            beast_request.body() = request.body();

            return target;
        }

        template <typename boost_beast_response_type, typename http_response_type>
        static inline void from_beast_http_response(http_response_type& result, boost_beast_response_type& beast_response)
        {
            result.clear();

            to_http_request_headers(result.headers(), beast_response);

            result.set_code(static_cast<uint16_t>(beast_response.result_int()));
            result.set_body(beast_response.body());
        }
    }
}
