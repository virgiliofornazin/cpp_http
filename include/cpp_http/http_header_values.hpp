/*
cpp_http library version 1.0.5

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
    class http_header_values
    {
    public:
        using values_type = std::vector<std::string>;
        
    private:
        std::string _name;
        values_type _values;

    private:
        void check_name()
        {
            if (_name.empty())
            {
                throw std::out_of_range("invalid http header name - empty name");
            }
        }

        void check_value(std::string_view const& value)
        {
            if (value.empty())
            {
                throw std::out_of_range(cpp_http_format::format("invalid http header {} - empty value", _name));
            }
        }

        void check_values(std::initializer_list<std::string>& values)
        {
            if (values.size() == 0)
            {
                throw std::out_of_range(cpp_http_format::format("invalid http header {} - empty values", _name));
            }

            for (auto& value: values)
            {
                check_value(value);
            }
        }
    
    public:
        http_header_values() = delete;
        
        http_header_values(http_header_values const&) = default;
        http_header_values(http_header_values&&) = default;
        
        http_header_values& operator = (http_header_values const&) = default;
        http_header_values& operator = (http_header_values&&) = default;

        explicit http_header_values(std::string_view const name)
            : _name(name)
        {
            check_name();
        }

        explicit http_header_values(std::string_view const name, std::string_view const value)
            : _name(name)
        {
            check_name();
            check_value(value);

            _values.emplace_back(value);
        }

        explicit http_header_values(std::string_view const name, std::initializer_list<std::string> values)
            : _name(name), _values(values)
        {
            check_name();
            check_values(values);
        }

        std::string const& name() const noexcept
        {
            return _name;
        }

        std::string const& value() const
        {
            return _values.at(0);        
        }

        values_type const& values() const noexcept
        {
            return _values;
        }

        void set_value(std::string_view const value)
        {
            check_value(value);

            _values.clear();
            _values.emplace_back(value);
        }

        void set_values(std::initializer_list<std::string> values)
        {
            check_values(values);            
            
            _values.clear();
            _values.insert(std::end(_values), std::begin(values), std::end(values));
        }

        void add_value(std::string_view const value)
        {
            check_value(value);
            
            _values.emplace_back(value);
        }

        void add_values(std::initializer_list<std::string> values)
        {
            check_values(values);

            _values.insert(std::end(_values), std::begin(values), std::end(values));
        }

        auto begin()
        {
            return std::begin(_values);
        }

        auto end()
        {
            return std::end(_values);
        }

        auto begin() const
        {
            return std::cbegin(_values);
        }

        auto end() const
        {
            return std::cend(_values);
        }

        auto cbegin() const
        {
            return std::cbegin(_values);
        }

        auto cend() const
        {
            return std::cend(_values);
        }

        auto rbegin()
        {
            return std::rbegin(_values);
        }

        auto rend()
        {
            return std::rend(_values);
        }

        auto rbegin() const
        {
            return std::crbegin(_values);
        }

        auto rend() const
        {
            return std::crend(_values);
        }

        auto crbegin() const
        {
            return std::crbegin(_values);
        }

        auto crend() const
        {
            return std::crend(_values);
        }

        size_t size() const noexcept
        {
            return _values.size();
        }
    };
}
