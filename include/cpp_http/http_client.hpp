#pragma once

#include "impl/config.hpp"
#include "impl/http_client_base.hpp"

namespace cpp_http
{
    class http_client
		: public impl::http_client_base
    {
    public:
        using request_callback = std::function<void(http_response::shared_ptr, std::string_view const)>;
    
    protected:
        template <typename http_stream_type, typename atomic_flag_type, typename callback_type>
        void do_execute_http_request(http_stream_type& http_stream, size_t const timeout_seconds, atomic_flag_type& timeout_flag, atomic_flag_type& callback_flag, callback_type& callback)
        {
            boost::beast::http::async_write(http_stream, _http_request,cpp_http_asio::bind_executor(_strand, 
                [this, timeout_seconds, timeout_flag, callback_flag, callback]
                (boost::beast::error_code ec, size_t bytes_transferred)
                    {
                        boost::ignore_unused(bytes_transferred);

                        if (ec || timeout_flag->test())
                        {
                            if (!callback_flag->test_and_set())
                            {
                                callback({}, cpp_http_format::format("error on http{} send [{}:{}]: {}", (_uri_protocol_is_secure ? "s" : ""), _uri_host, _uri_port_resolve, ec.message()));
                            }

                            disconnect();
                            
                            return;
                        }

                        boost::beast::http::async_read(_https_stream, _http_buffer, _http_response,cpp_http_asio::bind_executor(_strand, 
                            [this, timeout_seconds, timeout_flag, callback_flag, callback]
                            (boost::beast::error_code ec, size_t bytes_transferred)
                                {
                                    boost::ignore_unused(bytes_transferred);

                                    if (ec || timeout_flag->test())
                                    {
                                        if (!callback_flag->test_and_set())
                                        {
                                            callback({}, cpp_http_format::format("error on http{} receive [{}:{}]: {}", (_uri_protocol_is_secure ? "s" : ""), _uri_host, _uri_port_resolve, ec.message()));
                                        }

                                        disconnect();
                                        
                                        return;
                                    }

                                    disconnect();
                                    
                                    auto response_ptr = std::make_shared<http_response>();
                                    
                                    impl::from_beast_http_response(*response_ptr.get(), _http_response);

                                    debug_info([&]() { return cpp_http_format::format("http{} async response received:\n{}", (_uri_protocol_is_secure ? "s" : ""), response_ptr->to_string()); });

                                    if (!callback_flag->test_and_set())
                                    {
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
		
		explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<size_t> default_timeout_seconds)
			: http_client_base(ioc, uri_protocol_is_secure, "http", uri_host, uri_port, uri_path, default_timeout_seconds)
		{
		}

		explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
			: http_client(ioc, uri_protocol_is_secure, uri_host, uri_port, uri_path, {})
		{
		}

		explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<size_t> default_timeout_seconds)
			: http_client(ioc, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_seconds)
		{
		}

		explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
			: http_client(ioc, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), {})
		{
		}

		explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<size_t> default_timeout_seconds)
			: http_client(ioc, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_seconds)
		{
		}

		explicit http_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host)
        	: http_client(ioc, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), {})
		{
		}

		http_response execute(http_request& request, std::optional<size_t> request_timeout_seconds = {})
        {
            if (request_timeout_seconds.has_value() || _default_timeout_seconds.has_value())
            {
                return execute(std::make_shared<http_request>(request), request_timeout_seconds);
            }

            auto resolved = _resolver.resolve(_uri_host, _uri_port_resolve);

            before_execute(request);

            impl::to_beast_http_request(_http_request, request, *this);

            debug_info([&]() { return cpp_http_format::format("http sync request:\n{}", request.to_string(_uri_path)); });
            
            _http_response = {};

            if (_uri_protocol_is_secure)
            {
                if(! SSL_set_tlsext_host_name(_https_stream.native_handle(), _uri_host.c_str()))
                {
                    auto ec = boost::beast::error_code(static_cast<int>(::ERR_get_error()),cpp_http_asio::error::get_ssl_category());
                    
                    throw boost::beast::system_error{ec};
                }

                boost::beast::get_lowest_layer(_https_stream).connect(resolved);

                _https_stream.handshake(cpp_http_asio::ssl::stream_base::client);

                boost::beast::http::write(_https_stream, _http_request);
                boost::beast::http::read(_https_stream, _http_buffer, _http_response);
            }
            else
            {
                _http_stream.connect(resolved);

                boost::beast::http::write(_http_stream, _http_request);
                boost::beast::http::read(_http_stream, _http_buffer, _http_response);
            }
            
            disconnect();

			http_response response;
            
			impl::from_beast_http_response(response, _http_response);

            debug_info([&]() { return cpp_http_format::format("http sync response received:\n{}", response.to_string()); });

            return response;
        }

        http_response execute(http_request::shared_ptr request_ptr, std::optional<size_t> request_timeout_seconds = {})
        {
            if (request_timeout_seconds.has_value() || _default_timeout_seconds.has_value())
            {
                http_response::shared_ptr execute_response_ptr;
                std::string execute_error_message;
                std::mutex wait_mutex;

                wait_mutex.lock();

                execute_async(request_ptr, [&execute_response_ptr, &execute_error_message, &wait_mutex](http_response::shared_ptr response_ptr, std::string_view const error_message)
                    {
                        execute_response_ptr = response_ptr;
                        execute_error_message = error_message;

                        wait_mutex.unlock();
                    }
                    , request_timeout_seconds);

                wait_mutex.lock();

                if (execute_error_message.empty())
                {
                    return std::move(*execute_response_ptr);
                }
                
                throw std::runtime_error(execute_error_message);
            }
            
            return execute(*request_ptr.get(), request_timeout_seconds);
        }
		
        void execute_async(http_request& request, request_callback callback, std::optional<size_t> request_timeout_seconds = {})
        {
            execute_async(std::make_shared<cpp_http::http_request>(request), callback, request_timeout_seconds);
        }

        void execute_async(http_request::shared_ptr request_ptr, request_callback callback, std::optional<size_t> request_timeout_seconds = {})
        {
            auto timeout_seconds = request_timeout_seconds.has_value() ? request_timeout_seconds.value_or(0) : _default_timeout_seconds.value_or(0);
            auto callback_called = std::make_shared<cpp_http_atomic_flag>(false);
            auto request_timed_out = std::make_shared<cpp_http_atomic_flag>(false);
            
            if (timeout_seconds)
            {
                _timer.expires_from_now(boost::posix_time::seconds(timeout_seconds));
                _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                    [this, request_timed_out, callback_called, callback]
                    (boost::system::error_code ec)
                        {
                            boost::ignore_unused(ec);

                            if (!callback_called->test_and_set())
                            {
                                request_timed_out->test_and_set();

	                            disconnect();

                                callback({}, "http request execution timeout out");
                            }
                        }));
            }

            connect_async(
                [this, request_ptr, timeout_seconds, request_timed_out, callback_called, callback]
                (std::string_view const error_message)
                    {
                        if (!error_message.empty() || request_timed_out->test())
                        {
                            if (!callback_called->test_and_set())
                            {
                                callback({}, error_message);
                            }

                            disconnect();

                            return;
                        }

                        before_execute(*request_ptr.get());

                        impl::to_beast_http_request(_http_request, *request_ptr.get(), *this);

                        debug_info([&]() { return cpp_http_format::format("http{} async request:\n{}", (_uri_protocol_is_secure ? "s" : ""), request_ptr->to_string(_uri_path)); });

                        if (_uri_protocol_is_secure)
                        {
                            if (timeout_seconds)
                            {
                                boost::beast::get_lowest_layer(_https_stream).expires_after(std::chrono::seconds(timeout_seconds));
                            }

                            do_execute_http_request(_https_stream, timeout_seconds, request_timed_out, callback_called, callback);
                        }
                        else
                        {
                            if (timeout_seconds)
                            {
                                _http_stream.expires_after(std::chrono::seconds(timeout_seconds));
                            }

                            do_execute_http_request(_http_stream, timeout_seconds, request_timed_out, callback_called, callback);
                        }
                    }, 0);
        }
        
    public:
	    using shared_ptr = std::shared_ptr<http_client>;
    };
}
