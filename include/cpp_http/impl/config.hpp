/*
cpp_http library version 1.0.1

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

#if __has_include(<asio/asio.hpp>) && !defined(CPP_HTTP_NO_STANDALONE_ASIO)
#include <asio/asio.hpp>
namespace cpp_http_asio = ::asio;
#elif __has_include(<boost/asio.hpp>)
#include <boost/asio.hpp>
namespace cpp_http_asio = ::boost::asio;
#else /* __has_include(asio?) */
#error (boost::)asio library not detected in include path
#endif /* __has_include(asio?) */

#if __has_include(<format>) && !defined(CPP_HTTP_NO_STD_FORMAT)
#include <format>
namespace cpp_http_format = ::std;
#elif __has_include(<fmt/format.h>)
#include <fmt/format.h>
namespace cpp_http_format = ::fmt;
#else /* __has_include(format?) */
#error (std/fmt)::format not detected in include path
#endif /* __has_include(format?) */

#if !__has_include(<boost/beast/core.hpp>)
#error boost::beast library not detected in include path
#endif /* !__has_include(<boost/beast/core.hpp>) */

#if !__has_include(<boost/url/url.hpp>)
#error boost::url library not detected in include path
#endif /* !__has_include(<boost/url/url.hpp>) */

#if !__has_include(<boost/json.hpp>)
#error boost::json library not detected in include path
#endif /* !__has_include(<boost/json.hpp>) */

#if defined(CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES) || defined(CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES)
#ifndef CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
#define CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
#endif /* CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES */
#ifndef CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
#define CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
#endif /* CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES */
#endif /* defined(CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES) || defined(CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES) */

#ifndef CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
// #define CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
#define CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
#endif /* CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES */

#include "stl_headers.hpp"
#include "library_version.hpp"
