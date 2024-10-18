#pragma once

#include "config.hpp"
#include "http_client_utils.inl"
#include "../http_request.hpp"
#include "../http_response.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <functional>
#include <stdexcept>
#include <optional>

namespace cpp_http
{
    namespace impl
    {
        class http_client_base
        {
        protected:
            using connect_callback = std::function<void(std::string_view const)>;

        public:
            using debug_info_expression_generator = std::function<std::string()>;

        protected:
            cpp_http_asio::io_context & _ioc;
            cpp_http_asio::io_context::strand _strand;
            cpp_http_asio::ssl::context _ssl;
            cpp_http_asio::deadline_timer _timer;
            cpp_http_asio::ip::tcp::resolver _resolver;
            boost::beast::flat_buffer _http_buffer;
            boost::beast::tcp_stream _http_stream;
            cpp_http_asio::ssl::stream<boost::beast::tcp_stream> _https_stream;
            boost::beast::http::request<boost::beast::http::string_body> _http_request;
            boost::beast::http::response<boost::beast::http::string_body> _http_response;
            std::string _http_host_string;
            std::string _http_target_string;            
            std::string _user_agent;
            std::string _uri;
            bool _uri_protocol_is_secure = {};
            std::string _uri_protocol;
            std::string _uri_host;
            std::string _uri_port;
            std::string _uri_port_resolve;
            std::string _uri_path;
            std::optional<size_t> _default_timeout_seconds;

        protected:
            virtual void before_execute(http_request& request /* info */)
            {
            }
            
            virtual void debug_info(debug_info_expression_generator /* info */)
            {
            }

        private:
            template <typename error_code_type, typename http_stream_type, typename atomic_flag_type, typename callback_type>
            void on_connect_completed(error_code_type& ec, http_stream_type& http_stream, size_t const timeout_seconds, atomic_flag_type& timeout_flag, atomic_flag_type& callback_flag, callback_type& callback, debug_info_expression_generator info)
            {
                if (ec || timeout_flag->test())
                {
                    if (!callback_flag->test_and_set())
                    {
                        callback(info());
                    }
                    
                    disconnect();
                    
                    return;
                }
                        
                if (timeout_seconds)
                {
                    http_stream.expires_never();

                    _timer.cancel();
                }

                if (!callback_flag->test_and_set())
                {
                    callback({});
                }
            }

        protected:
            void update_uri()
            {
                http_update_uri(_uri_protocol_is_secure, _uri_protocol, _uri_host, _uri_port, _uri_path, _uri, _uri_port_resolve);
            }

            void connect(std::optional<size_t> connection_timeout_seconds = {})
            {
                std::string connection_error_message;
                std::mutex wait_mutex;

                wait_mutex.lock();

                connect_async([&connection_error_message, &wait_mutex](std::string_view const error_message)
                    {
                        connection_error_message = error_message;

                        wait_mutex.unlock();
                    }
                    , connection_timeout_seconds);

                wait_mutex.lock();

                if (connection_error_message.empty())
                {
                    throw std::runtime_error(connection_error_message);
                }
            }

            void connect_async(connect_callback callback, std::optional<size_t> connection_timeout_seconds = {})
            {
                auto timeout_seconds = connection_timeout_seconds.has_value() ? connection_timeout_seconds.value_or(0) : _default_timeout_seconds.value_or(0);
                auto callback_called = std::make_shared<cpp_http_atomic_flag>();
                auto connection_timed_out = std::make_shared<cpp_http_atomic_flag>();
                
                if (timeout_seconds)
                {
                    _timer.expires_from_now(boost::posix_time::seconds(timeout_seconds));
                    _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                        [this, connection_timed_out, callback_called, callback]
                        (boost::system::error_code ec)
                            {
                                boost::ignore_unused(ec);

                                if (!callback_called->test_and_set())
                                {
                                    connection_timed_out->test_and_set();

                                    disconnect();

                                    callback(cpp_http_format::format("connection to {}:{} timed out", _uri_host, _uri_port_resolve));
                                }
                            }));
                }

                _resolver.async_resolve(_uri_host, _uri_port_resolve,cpp_http_asio::bind_executor(_strand, 
                    [this, timeout_seconds, connection_timed_out, callback_called, callback]
                    (boost::beast::error_code ec,cpp_http_asio::ip::tcp::resolver::results_type resolved)
                        {
                            if (ec || connection_timed_out->test())
                            {
                                if (!callback_called->test_and_set())
                                {
                                    callback(cpp_http_format::format("error on resolve [{}:{}]: {}", _uri_host, _uri_port_resolve, ec.message()));
                                }

                                disconnect();
                                
                                return;
                            }

                            _http_host_string = http_sni_host_string(_uri_protocol_is_secure, _uri_host, _uri_port);

                            if (_uri_protocol_is_secure)
                            {
                                if (timeout_seconds)
                                {
                                    boost::beast::get_lowest_layer(_https_stream).expires_after(std::chrono::seconds(timeout_seconds));
                                }

                                boost::beast::get_lowest_layer(_https_stream).async_connect(resolved,cpp_http_asio::bind_executor(_strand, 
                                    [this, timeout_seconds, connection_timed_out, callback_called, callback]
                                    (boost::beast::error_code ec,cpp_http_asio::ip::tcp::resolver::results_type::endpoint_type ep)
                                        {
                                            boost::ignore_unused(ep);

                                            if (ec || connection_timed_out->test())
                                            {
                                                if (!callback_called->test_and_set())
                                                {
                                                    callback(cpp_http_format::format("error on connect [{}:{}]: {}", _uri_host, _uri_port_resolve, ec.message()));
                                                }

                                                disconnect();
                                                
                                                return;
                                            }

                                            if (!SSL_set_tlsext_host_name(_https_stream.native_handle(), _http_host_string.c_str()))
                                            {
                                                auto ec = boost::beast::error_code(static_cast<int>(::ERR_get_error()),cpp_http_asio::error::get_ssl_category());
                                                
                                                if (!callback_called->test_and_set())
                                                {
                                                    callback(cpp_http_format::format("error on SSL setup for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()));
                                                }

                                                disconnect();
                                                
                                                return;
                                            }
                                    
                                            _https_stream.async_handshake(cpp_http_asio::ssl::stream_base::client,cpp_http_asio::bind_executor(_strand, 
                                                [this, timeout_seconds, connection_timed_out, callback_called, callback]
                                                (boost::beast::error_code ec)
                                                    {
                                                        on_connect_completed(ec, boost::beast::get_lowest_layer(_https_stream), timeout_seconds, connection_timed_out, callback_called, callback,
                                                            [this, ec]() { return cpp_http_format::format("error on SSL handshake for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()); });
                                                    }));
                                        }));
                            }
                            else
                            {
                                if (timeout_seconds)
                                {
                                    _http_stream.expires_after(std::chrono::seconds(timeout_seconds));
                                }

                                _http_stream.async_connect(resolved,cpp_http_asio::bind_executor(_strand,  
                                    [this, timeout_seconds, connection_timed_out, callback_called, callback]
                                    (boost::beast::error_code ec, cpp_http_asio::ip::tcp::resolver::results_type::endpoint_type ep)
                                        {
                                            boost::ignore_unused(ep);
                                            
                                            on_connect_completed(ec, _http_stream, timeout_seconds, connection_timed_out, callback_called, callback,
                                                [this, ec]() { return cpp_http_format::format("error on connect for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()); });
                                        }));
                            }
                        }));
            }
            
        public:
            http_client_base() = delete;
            
            http_client_base(http_client_base const&) = delete;
            http_client_base(http_client_base&&) = delete;

            http_client_base& operator = (http_client_base const&) = delete;
            http_client_base& operator = (http_client_base&&) = delete;

            virtual ~http_client_base() noexcept = default;
            
            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<size_t> default_timeout_seconds)
                : _ioc(ioc), _strand(ioc), _ssl(cpp_http_asio::ssl::context::sslv23_client), _timer(ioc), _resolver(cpp_http_asio::make_strand(ioc)), _http_stream(ioc), _https_stream(ioc, _ssl), _user_agent("cpp_http/1.0")
                , _uri_protocol_is_secure(uri_protocol_is_secure), _uri_protocol(uri_protocol), _uri_host(uri_host), _uri_port(uri_port), _uri_path(uri_path), _default_timeout_seconds(default_timeout_seconds)
            {
                update_uri();
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, uri_path, {})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::optional<size_t> default_timeout_seconds)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), default_timeout_seconds)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), {})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::optional<size_t> default_timeout_seconds)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), default_timeout_seconds)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), {})
            {
            }

            std::string const& user_agent() const noexcept
            {
                return _user_agent;
            }

            void set_user_agent(std::string_view const user_agent)
            {
                _user_agent = user_agent;
            }

            std::string const& uri() const noexcept
            {
                return _uri;
            }

            bool uri_protocol_is_secure() const noexcept
            {
                return _uri_protocol_is_secure;
            }

            void set_uri_protocol_is_secure(bool const uri_protocol_is_secure)
            {
                _uri_protocol_is_secure = uri_protocol_is_secure;

                update_uri();
            }

            std::string const& uri_protocol() const noexcept
            {
                return _uri_protocol;
            }

            void set_uri_protocol(std::string_view const uri_protocol)
            {
                _uri_protocol = uri_protocol;

                update_uri();
            }

            std::string const& uri_host() const noexcept
            {
                return _uri_host;
            }

            void set_uri_host(std::string_view const uri_host)
            {
                _uri_host = uri_host;

                update_uri();
            }

            std::string const& uri_port() const noexcept
            {
                return _uri_port;
            }

            void set_uri_port(std::string_view const uri_port)
            {
                _uri_port = uri_port;

                update_uri();
            }

            std::string const& uri_path() const noexcept
            {
                return _uri_path;
            }

            void set_uri_path(std::string_view const uri_path)
            {
                _uri_path = uri_path;

                update_uri();
            }

            std::optional<size_t> const& default_timeout_seconds() const noexcept
            {
                return _default_timeout_seconds;
            }

            void set_default_timeout_seconds(std::optional<size_t> default_timeout_seconds = {})
            {
                _default_timeout_seconds = default_timeout_seconds;
            }

            void disconnect()
            {
                try
                {
                    _timer.cancel();
                }
                catch (std::exception const&)
                {
                }

                if (_uri_protocol_is_secure)
                {
                    try
                    {
                        boost::beast::get_lowest_layer(_https_stream).expires_never();
                    }
                    catch (std::exception const&)
                    {
                    }

                    try
                    {
                        boost::beast::error_code ec;

                        _https_stream.shutdown(ec);
                    }
                    catch (std::exception const&)
                    {
                    }

                    try
                    {
                        boost::system::error_code ec;
                        
                        auto& socket = boost::beast::get_lowest_layer(_https_stream).socket();
                            
                        socket.shutdown(cpp_http_asio::ip::tcp::socket::shutdown_both, ec);
                        socket.close(ec);
                    }
                    catch (std::exception const&)
                    {
                    }
                }
                else
                {
                    try
                    {
                        _http_stream.expires_never();
                    }
                    catch (std::exception const&)
                    {
                    }
                    
                    try
                    {
                        boost::system::error_code ec;

                        auto& socket = _http_stream.socket();
                            
                        socket.shutdown(cpp_http_asio::ip::tcp::socket::shutdown_both, ec);
                        socket.close(ec);
                    }
                    catch (std::exception const&)
                    {
                    }
                }
            }
        };
    }
}
