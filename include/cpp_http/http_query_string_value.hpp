/*
cpp_http library version 1.0.2

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
