#pragma once

#include <chrono>
#include <string_view>
#include <string>
#include <memory>
#include <cstdint>
#include <atomic>

using cpp_http_timeout_clock_type = std::chrono::steady_clock;
using cpp_http_timeout_time_point_type = typename cpp_http_timeout_clock_type::time_point;

#if __cplusplus >= 202002L
using cpp_http_atomic_flag = std::atomic_flag;
#else
#include "atomic_flag.hpp"
using cpp_http_atomic_flag = cpp_http::impl::atomic_flag;
#endif
