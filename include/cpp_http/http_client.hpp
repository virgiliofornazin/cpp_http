#pragma once

#include "impl/config.hpp"
#include "impl/http_client_base.hpp"
#include <chrono>
#include <ratio>

namespace cpp_http
{
    class http_client
        : public impl::http_client_base
    {
    public:
        using request_callback = std::function<void(http_response::shared_ptr, std::string_view const)>;
    
    protected:
        boost::beast::tcp_stream _http_stream;
        cpp_http_asio::ssl::stream<boost::beast::tcp_stream> _https_stream;
        boost::beast::http::request<boost::beast::http::string_body> _http_request;
        boost::beast::http::response<boost::beast::http::string_body> _http_response;

    protected:
        virtual boost::beast::tcp_stream* beast_tcp_stream() override
        {
            return std::addressof(_uri_protocol_is_secure ? boost::beast::get_lowest_layer(_https_stream) : _http_stream);
        }

        virtual cpp_http_asio::ssl::stream<boost::beast::tcp_stream>* asio_ssl_stream() override
        {
            return std::addressof(_https_stream);
        }
            
    protected:
        template <typename http_stream_type, typename duration_type, typename atomic_flag_type, typename callback_type>
        void do_execute_http_request(http_stream_type& http_stream, duration_type const& timeout_interval, atomic_flag_type& request_timed_out, atomic_flag_type& callback_called, callback_type& callback)
        {
            if (timeout_interval.count() > 0)
            {
                auto tcp_stream = beast_tcp_stream();

                if (!tcp_stream)
                {
                    throw std::logic_error("tcp_stream() failed");
                }

                tcp_stream->expires_after(std::chrono::duration_cast<std::chrono::milliseconds>(timeout_interval));
            }
            
            boost::beast::http::async_write(http_stream, _http_request, cpp_http_asio::bind_executor(_strand, 
                [this, &http_stream, request_timed_out, callback_called, callback]
                (boost::beast::error_code ec, size_t bytes_transferred) mutable
                    {
                        boost::ignore_unused(bytes_transferred);

                        if (ec || request_timed_out->test())
                        {
                            auto should_callback = !callback_called->test_and_set();

                            if (should_callback)
                            {
                                callback({}, cpp_http_format::format("error on http{} send [{}:{}]: {}", (_uri_protocol_is_secure ? "s" : ""), _uri_host, _uri_port_resolve, ec.message()));
                            }

                            disconnect();
                            
                            return;
                        }

                        boost::beast::http::async_read(http_stream, _flat_buffer, _http_response, cpp_http_asio::bind_executor(_strand, 
                            [this, request_timed_out, callback_called, callback]
                            (boost::beast::error_code ec, size_t bytes_transferred) mutable
                                {
                                    boost::ignore_unused(bytes_transferred);

                                    auto should_callback = !callback_called->test_and_set();

                                    disconnect();
                                        
                                    if (ec || request_timed_out->test())
                                    {
                                        if (should_callback)
                                        {
                                            callback({}, cpp_http_format::format("error on http{} receive [{}:{}]: {}", (_uri_protocol_is_secure ? "s" : ""), _uri_host, _uri_port_resolve, ec.message()));
                                        }

                                        return;
                                    }
                                    
                                    if (should_callback)
                                    {
                                        auto response_ptr = std::make_shared<http_response>();
                                        
                                        impl::from_beast_http_response(*response_ptr.get(), _http_response);

                                        debug_info([&]() { return cpp_http_format::format("http{} async response received:\n{}", (_uri_protocol_is_secure ? "s" : ""), response_ptr->to_string()); });

                                        callback(response_ptr, {});
                                    }
                                }));
                    }));
        }

    public:
        http_client() = delete;

        http_client(http_client const&) = delete;
        http_client(http_client&&) = delete;

        http_client& operator = (http_client const&) = delete;
        http_client& operator = (http_client&&) = delete;

        template <typename duration_type = std::chrono::milliseconds>
        explicit http_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
            : http_client_base(ioc, sslc, uri_protocol_is_secure, "http", uri_host, uri_port, uri_path, default_timeout_interval), _http_stream(boost::asio::make_strand(ioc)), _https_stream(boost::asio::make_strand(ioc), _sslc)
        {
        }

        template <typename duration_type = std::chrono::milliseconds>
        explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
            : http_client_base(ioc, uri_protocol_is_secure, "http", uri_host, uri_port, uri_path, default_timeout_interval), _http_stream(boost::asio::make_strand(ioc)), _https_stream(boost::asio::make_strand(ioc), _sslc)
        {
        }

        explicit http_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
            : http_client(ioc, sslc, uri_protocol_is_secure, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
            : http_client(ioc, uri_protocol_is_secure, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
        {
        }

        template <typename duration_type>
        explicit http_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
            : http_client(ioc, sslc, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
            : http_client(ioc, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_interval)
        {
        }

        explicit http_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
            : http_client(ioc, sslc, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
            : http_client(ioc, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        template <typename duration_type>
        explicit http_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
            : http_client(ioc, sslc, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
            : http_client(ioc, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
        {
        }

        explicit http_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host)
            : http_client(ioc, sslc, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host)
            : http_client(ioc, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        template <typename duration_type = std::chrono::milliseconds>
        http_response execute(http_request& request, std::optional<duration_type> request_timeout_interval = {})
        {
            auto timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(request_timeout_interval.has_value() ? 
                request_timeout_interval.value_or(duration_type{}) : _default_timeout_interval.value_or(std::chrono::milliseconds{}));
            
            if (timeout_interval.count() > 0)
            {
                return execute(std::make_shared<http_request>(request), request_timeout_interval);
            }

            auto resolved = _resolver.resolve(_uri_host, _uri_port_resolve);

            before_execute(request);

            _http_host_string = impl::ssl_sni_host_string(_uri_protocol_is_secure, _uri_host, _uri_port);
            _http_target_string = impl::to_beast_http_request(_http_request, request, *this);

            debug_info([&]() { return cpp_http_format::format("http sync request:\n{}", request.to_string(_uri_path)); });
                    
            _http_response = {};

            if (_uri_protocol_is_secure)
            {
                if (!SSL_set_tlsext_host_name(_https_stream.native_handle(), _http_host_string.c_str()))
                {
                    auto ec = boost::beast::error_code(static_cast<int>(::ERR_get_error()),cpp_http_asio::error::get_ssl_category());
                    
                    throw boost::beast::system_error{ec};
                }
            }

            if (_uri_protocol_is_secure)
            {
                boost::beast::get_lowest_layer(_https_stream).connect(resolved);
                
                _https_stream.handshake(cpp_http_asio::ssl::stream_base::client);

                boost::beast::http::write(_https_stream, _http_request);
                boost::beast::http::read(_https_stream, _flat_buffer, _http_response);
            }
            else
            {
                _http_stream.connect(resolved);

                boost::beast::http::write(_http_stream, _http_request);
                boost::beast::http::read(_http_stream, _flat_buffer, _http_response);
            }
            
            disconnect();

            http_response response;
            
            impl::from_beast_http_response(response, _http_response);

            debug_info([&]() { return cpp_http_format::format("http sync response received:\n{}", response.to_string()); });

            return response;
        }

        template <typename duration_type = std::chrono::milliseconds>
        http_response execute(http_request::shared_ptr request_ptr, std::optional<duration_type> request_timeout_interval = {})
        {
            auto timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(request_timeout_interval.has_value() ? 
                request_timeout_interval.value_or(duration_type{}) : _default_timeout_interval.value_or(std::chrono::milliseconds{}));
            
            if (timeout_interval.count() > 0)
            {
                http_response::shared_ptr execute_response_ptr;
                std::string execute_error_message;
                std::mutex wait_mutex;

                wait_mutex.lock();

                execute_async(request_ptr, cpp_http_asio::bind_executor(_strand,  
                    [&execute_response_ptr, &execute_error_message, &wait_mutex]
                    (http_response::shared_ptr response_ptr, std::string_view const error_message) mutable
                        {
                            execute_response_ptr = response_ptr;
                            execute_error_message = error_message;

                            wait_mutex.unlock();
                        })
                        , request_timeout_interval);

                wait_mutex.lock();

                if (execute_error_message.empty())
                {
                    return std::move(*execute_response_ptr);
                }
                
                throw std::runtime_error(execute_error_message);
            }
            
            return execute(*request_ptr.get(), request_timeout_interval);
        }
        
        template <typename duration_type = std::chrono::milliseconds>
        void execute_async(http_request& request, request_callback callback, std::optional<duration_type> request_timeout_interval = {})
        {
            execute_async(std::make_shared<cpp_http::http_request>(request), callback, request_timeout_interval);
        }

        template <typename duration_type = std::chrono::milliseconds>
        void execute_async(http_request::shared_ptr request_ptr, request_callback callback, std::optional<duration_type> request_timeout_interval = {})
        {
            auto timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(request_timeout_interval.has_value() ? 
                request_timeout_interval.value_or(duration_type{}) : _default_timeout_interval.value_or(std::chrono::milliseconds{}));

            auto callback_called = std::make_shared<cpp_http_atomic_flag>(false);
            auto request_timed_out = std::make_shared<cpp_http_atomic_flag>(false);

            if (timeout_interval.count() > 0)
            {
                _timer.expires_from_now(boost::posix_time::milliseconds(timeout_interval.count()));
                _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                    [this, request_timed_out, callback_called, callback]
                    (boost::system::error_code ec) mutable
                        {
                            boost::ignore_unused(ec);

                            auto should_callback = !callback_called->test_and_set();

                            if (should_callback)
                            {
                                request_timed_out->test_and_set();

                                disconnect();

                                callback({}, "http request execution timeout out");
                            }
                        }));
            }

            do_connect_async(cpp_http_asio::bind_executor(_strand, 
                [this, request_ptr, timeout_interval, request_timed_out, callback_called, callback]
                (std::string_view const error_message) mutable
                    {
                        if (!error_message.empty() || request_timed_out->test())
                        {
                            auto should_callback = !callback_called->test_and_set();

                            if (should_callback)
                            {
                                callback({}, error_message);
                            }

                            disconnect();

                            return;
                        }

                        before_execute(*request_ptr.get());

                        _http_target_string = impl::to_beast_http_request(_http_request, *request_ptr.get(), *this);

                        debug_info([&]() { return cpp_http_format::format("http{} async request:\n{}", (_uri_protocol_is_secure ? "s" : ""), request_ptr->to_string(_uri_path)); });

                        if (_uri_protocol_is_secure)
                        {
                            do_execute_http_request(_http_stream, timeout_interval, request_timed_out, callback_called, callback);
                        }
                        else
                        {
                            do_execute_http_request(_https_stream, timeout_interval, request_timed_out, callback_called, callback);
                        }
                    })
                    , 0);
        }
        
    public:
        using shared_ptr = std::shared_ptr<http_client>;
    };
}
