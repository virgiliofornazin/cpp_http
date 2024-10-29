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

#include <string_view>
#include <string>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <optional>
#include <chrono>
#include <atomic>
#include <memory>
#include <ostream>
#include <sstream>
#include <iterator>
#include <algorithm>
#include <functional>
#include <vector>
#include <queue>
#ifdef CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
#include <deque>
#endif /* CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES */
#if __cplusplus < 202002L
#include "atomic_flag.hpp"
#endif /* __cplusplus < 202002L */

namespace cpp_http
{
   using timeout_clock = std::chrono::steady_clock;
   using timeout_time_point = typename cpp_http::timeout_clock::time_point;

#if __cplusplus >= 202002L
   using atomic_flag = std::atomic_flag;
#else /* __cplusplus >= 202002L */
   using atomic_flag = cpp_http::impl::atomic_flag;
#endif /* __cplusplus >= 202002L */
}
