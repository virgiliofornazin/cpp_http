#pragma once

#include "impl/config.hpp"
#include <ostream>

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
