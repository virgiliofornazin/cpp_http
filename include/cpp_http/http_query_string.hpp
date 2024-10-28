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

#include "impl/config.hpp"
#include "impl/http_utils.inl"
#include "http_query_string_value.hpp"

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
