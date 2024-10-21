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

        private:
            cpp_http_asio::ssl::context _sslc_internal;

        protected:
            cpp_http_asio::io_context& _ioc;
            cpp_http_asio::io_context::strand _strand;
            cpp_http_asio::ssl::context& _sslc;
            cpp_http_asio::deadline_timer _timer;
            cpp_http_asio::ip::tcp::resolver _resolver;
            boost::beast::flat_buffer _flat_buffer;
            bool _connected = {};
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
            virtual boost::beast::tcp_stream* beast_tcp_stream()
            {
                return nullptr;
            }
            
            virtual cpp_http_asio::ssl::stream<boost::beast::tcp_stream>* asio_ssl_stream()
            {
                return nullptr;
            }
            
            virtual boost::asio::ip::tcp::socket* asio_tcp_socket()
            {
                auto tcp_stream = beast_tcp_stream();

                if (tcp_stream)
                {
                    return std::addressof(tcp_stream->socket());
                }

                return nullptr;
            }
            
        protected:
            virtual void before_execute(http_request& request /* info */)
            {
            }
            
            virtual void debug_info(debug_info_expression_generator /* info */)
            {
            }

        private:           

            template <typename error_code_type, typename atomic_flag_type, typename callback_type>
            void on_connect_completed(error_code_type& ec, size_t const timeout_seconds, atomic_flag_type& connection_timed_out, atomic_flag_type& callback_called, callback_type& callback, debug_info_expression_generator info)
            {
                auto should_callback = !callback_called->test_and_set();

                if (ec || connection_timed_out->test())
                {
                    if (should_callback)
                    {
                        callback(info());
                    }
                    
                    disconnect();
                    
                    return;
                }
                        
                if (timeout_seconds)
                {
                    auto tcp_stream = beast_tcp_stream();

                    if (tcp_stream)
                    {
                        tcp_stream->expires_never();
                    }

                    _timer.cancel();
                }

                if (should_callback)
                {
                    _connected = true;

                    callback({});
                }
            }

        protected:
            void throw_if_connected()
            {
                if (_connected)
                {
                    throw std::logic_error("cannot change parameters of an already estabilished connection");
                }
            }

            void update_uri()
            {
                http_update_uri(_uri_protocol_is_secure, _uri_protocol, _uri_host, _uri_port, _uri_path, _uri, _uri_port_resolve);
            }

            void do_cancel_timer()
            {
                try
                {
                    _timer.cancel();
                }
                catch (std::exception const&)
                {
                }
            }
            
            void do_shutdown_beast_tcp_stream()
            {
                auto tcp_stream = beast_tcp_stream();

                if (tcp_stream)
                {
                    try
                    {
                        tcp_stream->expires_never();
                    }
                    catch (std::exception const&)
                    {
                    }
                }
            }
            
            void do_close_asio_ssl_stream()
            {
                auto ssl_stream = asio_ssl_stream();

                if (ssl_stream)
                {
                    try
                    {
                        boost::beast::error_code ec;

                        ssl_stream->shutdown(ec);
                    }
                    catch (std::exception const&)
                    {
                    }
                }                
            }
            
            void do_close_asio_tcp_socket()
            {
                auto tcp_socket = asio_tcp_socket();

                if (tcp_socket)
                {
                    try
                    {
                        boost::system::error_code ec;
                        
                        tcp_socket->shutdown(cpp_http_asio::ip::tcp::socket::shutdown_both, ec);
                        tcp_socket->close(ec);
                    }
                    catch (std::exception const&)
                    {
                    }
                }
            }

            void do_connect(std::optional<size_t> connection_timeout_seconds = {})
            {
                std::string connection_error_message;
                std::mutex wait_mutex;

                wait_mutex.lock();

                do_connect_async([&connection_error_message, &wait_mutex](std::string_view const error_message)
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

            void do_connect_async(connect_callback callback, std::optional<size_t> connection_timeout_seconds = {})
            {
                disconnect();
                
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

                                auto should_callback = !callback_called->test_and_set();

                                if (should_callback)
                                {
                                    connection_timed_out->test_and_set();

                                    disconnect();

                                    callback(cpp_http_format::format("connection to {}:{} timed out", _uri_host, _uri_port_resolve));
                                }
                            }));
                }

                _resolver.async_resolve(_uri_host, _uri_port_resolve, cpp_http_asio::bind_executor(_strand, 
                    [this, timeout_seconds, connection_timed_out, callback_called, callback]
                    (boost::beast::error_code ec,cpp_http_asio::ip::tcp::resolver::results_type resolved)
                        {
                            if (ec || connection_timed_out->test())
                            {
                                auto should_callback = !callback_called->test_and_set();

                                if (should_callback)
                                {
                                    callback(cpp_http_format::format("error on resolve [{}:{}]: {}", _uri_host, _uri_port_resolve, ec.message()));
                                }

                                disconnect();
                                
                                return;
                            }

                            _http_host_string = ssl_sni_host_string(_uri_protocol_is_secure, _uri_host, _uri_port);

                            auto tcp_stream = beast_tcp_stream();

                            if (!tcp_stream)
                            {
                                auto should_callback = !callback_called->test_and_set();

                                if (should_callback)
                                {
                                    callback("internal error : tcp_stream() failed");
                                }

                                return;
                            }

                            if (timeout_seconds)
                            {
                                tcp_stream->expires_after(std::chrono::seconds(timeout_seconds));
                            }
                                                
                            tcp_stream->async_connect(resolved, cpp_http_asio::bind_executor(_strand, 
                                [this, timeout_seconds, connection_timed_out, callback_called, callback]
                                (boost::beast::error_code ec,cpp_http_asio::ip::tcp::resolver::results_type::endpoint_type ep)
                                    {
                                        boost::ignore_unused(ep);

                                        if (ec || connection_timed_out->test())
                                        {
                                            auto should_callback = !callback_called->test_and_set();

                                            if (should_callback)
                                            {
                                                callback(cpp_http_format::format("error on connect [{}:{}]: {}", _uri_host, _uri_port_resolve, ec.message()));
                                            }

                                            disconnect();
                                            
                                            return;
                                        }

                                        if (_uri_protocol_is_secure)
                                        {
                                            auto ssl_stream = asio_ssl_stream();

                                            if (!ssl_stream)
                                            {
                                                auto should_callback = !callback_called->test_and_set();

                                                if (should_callback)
                                                {
                                                    callback("internal error : asio_ssl_stream() failed");
                                                }

                                                return;
                                            }

                                            if (!SSL_set_tlsext_host_name(ssl_stream->native_handle(), _http_host_string.c_str()))
                                            {
                                                auto should_callback = !callback_called->test_and_set();

                                                if (should_callback)
                                                {
                                                    auto ec = boost::beast::error_code(static_cast<int>(::ERR_get_error()),cpp_http_asio::error::get_ssl_category());
                                                
                                                    callback(cpp_http_format::format("error on SSL setup for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()));
                                                }

                                                disconnect();
                                                
                                                return;
                                            }
                                    
                                            ssl_stream->async_handshake(cpp_http_asio::ssl::stream_base::client, cpp_http_asio::bind_executor(_strand, 
                                                [this, timeout_seconds, connection_timed_out, callback_called, callback]
                                                (boost::beast::error_code ec)
                                                    {
                                                        on_connect_completed(ec, timeout_seconds, connection_timed_out, callback_called, callback,
                                                            [this, ec]() { return cpp_http_format::format("error on SSL handshake for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()); });
                                                    }));
                                        }
                                        else
                                        {
                                            on_connect_completed(ec, timeout_seconds, connection_timed_out, callback_called, callback,
                                                [this, ec]() { return cpp_http_format::format("error on connect for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()); });
                                        }
                                    }));
                        }));
            }
            
        public:
            http_client_base() = delete;
            
            http_client_base(http_client_base const&) = delete;
            http_client_base(http_client_base&&) = delete;

            http_client_base& operator = (http_client_base const&) = delete;
            http_client_base& operator = (http_client_base&&) = delete;

            virtual ~http_client_base() noexcept = default;

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<size_t> default_timeout_seconds)
                : _ioc(ioc), _strand(ioc), _sslc_internal(cpp_http_asio::ssl::context::sslv23_client), _sslc(sslc), _timer(boost::asio::make_strand(ioc)), _resolver(cpp_http_asio::make_strand(ioc)), _user_agent("cpp_http/1.0")
                , _uri_protocol_is_secure(uri_protocol_is_secure), _uri_protocol(uri_protocol), _uri_host(uri_host), _uri_port(uri_port), _uri_path(uri_path), _default_timeout_seconds(default_timeout_seconds)
            {
                update_uri();
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<size_t> default_timeout_seconds)
                : _ioc(ioc), _strand(ioc), _sslc_internal(cpp_http_asio::ssl::context::sslv23_client), _sslc(_sslc_internal), _timer(boost::asio::make_strand(ioc)), _resolver(cpp_http_asio::make_strand(ioc)), _user_agent("cpp_http/1.0")
                , _uri_protocol_is_secure(uri_protocol_is_secure), _uri_protocol(uri_protocol), _uri_host(uri_host), _uri_port(uri_port), _uri_path(uri_path), _default_timeout_seconds(default_timeout_seconds)
            {
                update_uri();
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, uri_path, {})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, uri_path, {})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::optional<size_t> default_timeout_seconds)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), default_timeout_seconds)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::optional<size_t> default_timeout_seconds)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), default_timeout_seconds)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), {})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), {})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::optional<size_t> default_timeout_seconds)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), default_timeout_seconds)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::optional<size_t> default_timeout_seconds)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), default_timeout_seconds)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), {})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), {})
            {
            }

            bool connected() const noexcept
            {
                return _connected;
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
                throw_if_connected();

                _uri_protocol_is_secure = uri_protocol_is_secure;

                update_uri();
            }

            std::string const& uri_protocol() const noexcept
            {
                return _uri_protocol;
            }

            void set_uri_protocol(std::string_view const uri_protocol)
            {
                throw_if_connected();

                _uri_protocol = uri_protocol;

                update_uri();
            }

            std::string const& uri_host() const noexcept
            {
                return _uri_host;
            }

            void set_uri_host(std::string_view const uri_host)
            {
                throw_if_connected();

                _uri_host = uri_host;

                update_uri();
            }

            std::string const& uri_port() const noexcept
            {
                return _uri_port;
            }

            void set_uri_port(std::string_view const uri_port)
            {
                throw_if_connected();

                _uri_port = uri_port;

                update_uri();
            }

            std::string const& uri_path() const noexcept
            {
                return _uri_path;
            }

            void set_uri_path(std::string_view const uri_path)
            {
                throw_if_connected();

                _uri_path = uri_path;

                update_uri();
            }

            std::optional<size_t> const& default_timeout_seconds() const noexcept
            {
                return _default_timeout_seconds;
            }

            void set_default_timeout_seconds(std::optional<size_t> default_timeout_seconds = {})
            {
                throw_if_connected();

                _default_timeout_seconds = default_timeout_seconds;
            }

            void disconnect()
            {
                _connected = false;

                do_cancel_timer();
                do_shutdown_beast_tcp_stream();
                do_close_asio_ssl_stream();
                do_close_asio_tcp_socket();
            }
        };
    }
}
