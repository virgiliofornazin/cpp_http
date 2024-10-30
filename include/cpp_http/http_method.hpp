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

namespace cpp_http
{
    enum class http_method
    {
        get = 0,
        post = 1,
        put = 2,
        delete_ = 3,
        patch = 4,
        head = 5,
        options = 6
    };
};

namespace std
{
    static inline std::string to_string(cpp_http::http_method const method)
    {
        switch (method)
        {
        case cpp_http::http_method::get:
            {
                return "GET";
            }
        case cpp_http::http_method::post:
            {
                return "POST";
            }
        case cpp_http::http_method::put:
            {
                return "PUT";
            }
        case cpp_http::http_method::delete_:
            {
                return "DELETE";
            }
        case cpp_http::http_method::patch:
            {
                return "PATCH";
            }
        case cpp_http::http_method::head:
            {
                return "HEAD";
            }
        case cpp_http::http_method::options:
            {
                return "OPTIONS";
            }
        default:
            {
                return cpp_http_format::format("[invalid http_method value {}]", static_cast<size_t>(method));
            }
        }
    }
}
