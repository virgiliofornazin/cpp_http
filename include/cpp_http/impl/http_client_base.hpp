#pragma once

#include "config.hpp"
#include "http_client_utils.inl"
#include "../http_request.hpp"
#include "../http_response.hpp"
#include "stl_utils.inl"
#include "shared_object.hpp"
#include "diagnostics.inl"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <chrono>
#include <functional>
#include <stdexcept>

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
            bool _connected = false;
            bool _connection_in_progress = false;
            bool _assume_connected_on_transport_connection_succeeded = true;
            std::string _http_host_string;
            std::string _http_target_string;            
            std::string _user_agent;
            std::string _uri;
            bool _uri_protocol_is_secure = false;
            std::string _uri_protocol;
            std::string _uri_host;
            std::string _uri_port;
            std::string _uri_port_resolve;
            std::string _uri_path;
            std::optional<std::chrono::milliseconds> _default_timeout_interval;
            
        protected:
            virtual boost::beast::tcp_stream* beast_tcp_stream() noexcept
            {
                return nullptr;
            }
            
            virtual cpp_http_asio::ssl::stream<boost::beast::tcp_stream>* asio_ssl_stream() noexcept
            {
                return nullptr;
            }
            
            virtual cpp_http_asio::ip::tcp::socket* asio_tcp_socket() noexcept
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
            template <typename error_code_type, typename duration_type, typename atomic_flag_type, typename callback_type>
            void on_connect_completed(error_code_type& ec, std::optional<duration_type> const& timeout_interval, atomic_flag_type& connection_timed_out, atomic_flag_type& callback_called, callback_type& callback, debug_info_expression_generator info)
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

                if (timeout_interval && (timeout_interval->count() > 0))
                {
                    do_cancel_timer();
                }

                if (should_callback)
                {
                    _connected = _assume_connected_on_transport_connection_succeeded;
                    _connection_in_progress = !_connected;

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

            void do_cancel_timer() noexcept
            {
                try
                {
                    _timer.cancel();
                }
                catch (std::exception const&)
                {
                }
            }
            
            void do_shutdown_beast_tcp_stream() noexcept
            {
                auto tcp_stream = beast_tcp_stream();

                if (tcp_stream)
                {
                    try
                    {
                        tcp_stream->expires_after(std::chrono::milliseconds(1));
                    }
                    catch (std::exception const&)
                    {
                    }
                }    
            }
            
            void do_close_asio_ssl_stream() noexcept
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
            
            void do_close_asio_tcp_socket() noexcept
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

            template <typename current_type, typename duration_type = std::chrono::milliseconds>
            void connect(std::optional<duration_type> connection_timeout_interval = {})
            {
                std::string connection_error_message;
                std::mutex wait_mutex;

                wait_mutex.lock();

                connect_async<current_type>(
                    [&connection_error_message, &wait_mutex]
                    (std::string_view const error_message) mutable
                        {
                            connection_error_message = error_message;

                            wait_mutex.unlock();
                        }
                        , connection_timeout_interval);

                wait_mutex.lock();

                if (connection_error_message.empty())
                {
                    throw std::runtime_error(connection_error_message);
                }
            }

            template <typename current_type, typename duration_type = std::chrono::milliseconds>
            void connect_async(connect_callback callback, std::optional<duration_type> connection_timeout_interval = {})
            {
                disconnect();
                
                auto timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(connection_timeout_interval.has_value() ? 
                    connection_timeout_interval.value_or(std::chrono::milliseconds{}) : _default_timeout_interval.value_or(std::chrono::milliseconds{}));

                auto callback_called = std::make_shared<cpp_http_atomic_flag>();
                auto connection_timed_out = std::make_shared<cpp_http_atomic_flag>();

                do_connect_async<current_type>(callback_called, connection_timed_out, callback, timeout_interval);
            }

            template <typename current_type>
            void do_connect_async(std::shared_ptr<cpp_http_atomic_flag>& callback_called, std::shared_ptr<cpp_http_atomic_flag>& connection_timed_out, connect_callback callback, std::optional<std::chrono::milliseconds> timeout_interval = {})
            {
                disconnect();

                _connection_in_progress = true;

                auto self = dynamic_cast<current_type*>(this)->shared_from_this();

                if (timeout_interval && (timeout_interval->count() > 0))
                {
                    _strand.dispatch(
                        [this, self, connection_timed_out, callback_called, callback, timeout_interval]
                        ()
                            {
                                _timer.expires_from_now(boost::posix_time::milliseconds(timeout_interval->count()));
                                _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                                    [this, connection_timed_out, callback_called, callback]
                                    (boost::system::error_code ec) mutable
                                        {
                                            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "_timer.expired(connect), ec: " << ec; return ss.str(); });

                                            if (ec)
                                            {
                                                return;
                                            }

                                            auto should_callback = !callback_called->test_and_set();

                                            if (should_callback)
                                            {
                                                connection_timed_out->test_and_set();

                                                disconnect();

                                                callback(cpp_http_format::format("connection to {}:{} timed out", _uri_host, _uri_port_resolve));
                                            }
                                        }));
                            });
                }

                _strand.dispatch(
                    [this, self, timeout_interval, connection_timed_out, callback_called, callback]
                    ()
                    {
                        if (connection_timed_out->test())
                        {
                            return;
                        }

                        _resolver.async_resolve(_uri_host, _uri_port_resolve, cpp_http_asio::bind_executor(_strand, 
                            [this, self, timeout_interval, connection_timed_out, callback_called, callback]
                            (boost::beast::error_code ec,cpp_http_asio::ip::tcp::resolver::results_type resolved) mutable
                                {
                                    cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "_resolver.async_resolve(), ec: " << ec; return ss.str(); });

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
                                                        
                                    tcp_stream->async_connect(resolved, cpp_http_asio::bind_executor(_strand, 
                                        [this, self, timeout_interval, connection_timed_out, callback_called, callback]
                                        (boost::beast::error_code ec,cpp_http_asio::ip::tcp::resolver::results_type::endpoint_type ep) mutable
                                            {
                                                cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "tcp_stream.async_connect(), ec: " << ec; return ss.str(); });

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
                                                        [this, self, timeout_interval, connection_timed_out, callback_called, callback]
                                                        (boost::beast::error_code ec) mutable
                                                            {
                                                                cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "ssl_stream.async_handshake(), ec: " << ec; return ss.str(); });

                                                                on_connect_completed(ec, timeout_interval, connection_timed_out, callback_called, callback,
                                                                    [this, self, ec]() { return cpp_http_format::format("error on SSL handshake for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()); });
                                                            }));
                                                }
                                                else
                                                {
                                                    on_connect_completed(ec, timeout_interval, connection_timed_out, callback_called, callback,
                                                        [this, self, ec]() { return cpp_http_format::format("error on connect for host name {} [{}:{}]: {}", _http_host_string, _uri_host, _uri_port_resolve, ec.message()); });
                                                }
                                            }));
                                }));
                    });
            }
            
        public:
            http_client_base() = delete;
            
            http_client_base(http_client_base const&) = delete;
            http_client_base(http_client_base&&) = delete;

            http_client_base& operator = (http_client_base const&) = delete;
            http_client_base& operator = (http_client_base&&) = delete;

            virtual ~http_client_base() noexcept = default;

            template <typename duration_type = std::chrono::milliseconds>
            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
                : _ioc(ioc), _strand(ioc), _sslc_internal(cpp_http_asio::ssl::context::sslv23_client), _sslc(sslc), _timer(cpp_http_asio::make_strand(ioc)), _resolver(cpp_http_asio::make_strand(ioc)), _user_agent(cpp_http_format::format("cpp_http/{}", library_version()))
                , _uri_protocol_is_secure(uri_protocol_is_secure), _uri_protocol(uri_protocol), _uri_host(uri_host), _uri_port(uri_port), _uri_path(uri_path), _default_timeout_interval(optional_duration_cast_to_milliseconds(default_timeout_interval))
            {
                update_uri();
            }

            template <typename duration_type = std::chrono::milliseconds>
            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
                : _ioc(ioc), _strand(ioc), _sslc_internal(cpp_http_asio::ssl::context::sslv23_client), _sslc(_sslc_internal), _timer(cpp_http_asio::make_strand(ioc)), _resolver(cpp_http_asio::make_strand(ioc)), _user_agent(cpp_http_format::format("cpp_http/{}", library_version()))
                , _uri_protocol_is_secure(uri_protocol_is_secure), _uri_protocol(uri_protocol), _uri_host(uri_host), _uri_port(uri_port), _uri_path(uri_path), _default_timeout_interval(optional_duration_cast_to_milliseconds(default_timeout_interval))
            {
                update_uri();
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
            {
            }

            template <typename duration_type>
            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), default_timeout_interval)
            {
            }

            template <typename duration_type>
            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), default_timeout_interval)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::string_view const uri_port)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
            {
            }

            template <typename duration_type>
            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
            {
            }

            template <typename duration_type>
            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host)
                : http_client_base(ioc, sslc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
            {
            }

            explicit http_client_base(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_protocol, std::string_view const uri_host)
                : http_client_base(ioc, uri_protocol_is_secure, uri_protocol, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
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

            std::optional<std::chrono::milliseconds> const& default_timeout_interval() const noexcept
            {
                return _default_timeout_interval;
            }

            template <typename duration_type = std::chrono::milliseconds>
            void set_default_timeout_interval(std::optional<duration_type> default_timeout_interval = {})
            {
                throw_if_connected();

                _default_timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(default_timeout_interval);
            }

            virtual void disconnect() noexcept
            {
                auto connected = false;

                _connection_in_progress = false;
                std::swap(_connected, connected);

                do_cancel_timer();
                
                if (connected)
                {
                    do_shutdown_beast_tcp_stream();
                }

                do_close_asio_ssl_stream();
                do_close_asio_tcp_socket();
            }
        };
    }
}
