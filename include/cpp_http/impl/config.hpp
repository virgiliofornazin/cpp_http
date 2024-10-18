#pragma once

#include "stl_headers.hpp"

#if __has_include(<asio/asio.hpp>) && !defined(CPP_HTTP_NO_STANDALONE_ASIO)
#include <asio/asio.hpp>
namespace cpp_http_asio = ::asio;
#elif __has_include(<boost/asio.hpp>)
#include <boost/asio.hpp>
namespace cpp_http_asio = ::boost::asio;
#else
#error (boost::)asio library not detected in include path
#endif

#if __has_include(<format>) && !defined(CPP_HTTP_NO_STD_FORMAT)
#include <format>
namespace cpp_http_format = ::std;
#elif __has_include(<fmt/format.h>)
#include <fmt/format.h>
namespace cpp_http_format = ::fmt;
#else
#error (std/fmt)::format not detected in include path
#endif

#if !__has_include(<boost/beast/core.hpp>)
#error boost::beast library not detected in include path
#endif

#if !__has_include(<boost/url/url.hpp>)
#error boost::url library not detected in include path
#endif

#if !__has_include(<boost/json.hpp>)
#error boost::json library not detected in include path
#endif
