#pragma once

#include "impl/config.hpp"
#include "impl/http_utils.inl"
#include "http_method.hpp"
#include "http_query_string.hpp"
#include "http_headers.hpp"
#include <boost/json.hpp>
#include <ostream>
#include <sstream>

namespace cpp_http
{
    class http_request
    {
    private:
        http_method _method = http_method::get;
        std::string _uri_path;
        http_query_string _query_string;
        http_headers _headers;
        std::string _body;

    public:
        http_request() = default;
        
        http_request(http_request const&) = default;
        http_request(http_request&&) = default;
        
        http_request& operator = (http_request const&) = default;
        http_request& operator = (http_request&&) = default;

        explicit http_request(http_method method, http_headers const& headers = {})
            : _method(method), _headers(headers)
        {
        }

        explicit http_request(http_method method, std::string_view const uri_path, http_headers const& headers = {})
            : _method(method), _uri_path(uri_path), _headers(headers)
        {
        }

        http_method method() const noexcept
        {
            return _method;
        }

        void set_method(http_method const method)
        {
            _method = method;
        }

        std::string const& uri_path() const noexcept
        {
            return _uri_path;
        }

        void set_uri_path(std::string_view const uri_path)
        {
            _uri_path = uri_path;
        }

        http_query_string& query_string() noexcept
        {
            return _query_string;
        }

        http_query_string const& query_string() const noexcept
        {
            return _query_string;
        }

        template <typename http_query_string_type>
        void set_query_string(http_query_string_type&& query_string)
        {
            _query_string = std::forward<http_query_string_type>(query_string);
        }

        http_headers& headers() noexcept
        {
            return _headers;
        }

        http_headers const& headers() const noexcept
        {
            return _headers;
        }

        template <typename http_headers_type>
        void set_headers(http_headers_type&& headers)
        {
            _headers = std::forward<http_headers_type>(headers);
        }

        std::string& body() noexcept
        {
            return _body;
        }

        std::string const& body() const noexcept
        {
            return _body;
        }

        void set_body(std::string_view const body)
        {
            _body = body;
        }

        void set_json_body(boost::json::object const& object)
        {
            _body = boost::json::serialize(object);
        }

        void clear()
        {
            _method = http_method::get;
            _headers.clear();
            _body.clear();
        }

        using shared_ptr = std::shared_ptr<http_request>;
        
        shared_ptr clone()
        {
            return std::make_shared<http_request>(*this);
        }

        std::string to_string(std::string client_uri_path = {}) const
        {
            std::stringstream ss;
            
            ss  << std::to_string(_method) 
                << " " 
                << impl::http_encode_target(client_uri_path, _uri_path, _query_string) 
                << std::endl
                << _headers
                << std::endl
                << _body;

            return ss.str();
        }

        template <typename char_type, typename traits_type>
        friend inline std::basic_ostream<char_type, traits_type>& operator << (std::basic_ostream<char_type, traits_type>& os, http_request const& request)
        {
            return os << request.to_string();
        }
    };
}

namespace std
{
    static inline std::string to_string(cpp_http::http_request const& request)
    {
        return request.to_string();
    }
}
