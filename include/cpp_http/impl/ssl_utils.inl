#pragma once

#include "config.hpp"

namespace cpp_http
{
    namespace impl
    {
        static inline auto ssl_sni_host_string(bool const is_secure, std::string_view const host, std::string_view const port)
        {
            auto port_string = (port.empty()) || (!is_secure && port == "80") || (is_secure && port == "443")
                ? std::string() : cpp_http_format::format(":{}", port);

            return cpp_http_format::format("{}{}", host, port_string);
        }
    }
}
