/*
cpp_http library version 1.0.6

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

#include "impl/config.hpp"
#include "http_method.hpp"
#include "http_headers.hpp"
#include <boost/json.hpp>

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
