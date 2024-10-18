#pragma once

#include "impl/config.hpp"
#include "impl/http_client_base.hpp"
#include "http_query_string.hpp"
#include "websocket_event.hpp"
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <mutex>
#include <deque>

namespace cpp_http
{
    class websocket_client
        : public impl::http_client_base
    {
    public:
        using event_callback = std::function<void(websocket_event const, std::string_view const)>;

    protected:
        boost::beast::websocket::stream<boost::beast::tcp_stream> _ws_stream;
        boost::beast::websocket::stream<cpp_http_asio::ssl::stream<boost::beast::tcp_stream>> _wss_stream;
        size_t _websocket_receive_timeout_seconds = {};
        size_t _websocket_send_timeout_seconds = {};
        std::mutex _websocket_send_queue_mutex;
        std::deque<std::string> _websocket_high_priority_send_queue;
        std::deque<std::string> _websocket_send_queue;
        cpp_http_atomic_flag _websocket_send_busy;
        std::string _websocket_sending_message;
        cpp_http_timeout_time_point_type _websocket_receive_timestamp = {};
        cpp_http_timeout_time_point_type _websocket_send_timestamp = {};
        event_callback _callback;
    
    private:
        template <typename websocket_stream_type>
        void do_websocket_receive(websocket_stream_type& websocket_stream, std::string const& host_string, std::string const& target_string)
        {
            websocket_stream.async_read(_http_buffer, cpp_http_asio::bind_executor(_strand, 
                [this, &websocket_stream, host_string, target_string](boost::beast::error_code ec, size_t bytes_transferred)
                {
                    boost::ignore_unused(bytes_transferred);

                    if (ec)
                    {
                        _callback(websocket_event::receive_error, cpp_http_format::format("websocket receive error from [{}{}]: {}", host_string, target_string, ec.message()));
                        
                        disconnect();

                        _callback(websocket_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]: {}", host_string, target_string, ec.message()));

                        return;
                    }
                    
                    if (!websocket_stream.got_text())
                    {
                        _callback(websocket_event::receive_error, cpp_http_format::format("websocket receive no data from [{}{}]: {}", host_string, target_string, ec.message()));
                        
                        disconnect();

                        _callback(websocket_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]: {}", host_string, target_string, ec.message()));

                        return;
                    }

                    _websocket_receive_timestamp = cpp_http_timeout_clock_type::now();

                    _callback(websocket_event::message_received, boost::beast::buffers_to_string(_http_buffer.data()));
                    
                    _http_buffer.consume(_http_buffer.size());

                    do_websocket_receive(websocket_stream, host_string, target_string);
                }));
        }

        template <typename websocket_stream_type, typename atomic_flag_type>
        void do_websocket_handshake(std::string_view const error_message, http_query_string query_string, websocket_stream_type& websocket_stream, atomic_flag_type& timeout_flag, atomic_flag_type& callback_flag, std::optional<size_t> const& websocket_receive_timeout_seconds, std::optional<size_t> const& websocket_send_timeout_seconds, size_t const timeout_seconds)
        {
            if (!error_message.empty() || timeout_flag->test())
            {
                if (!callback_flag->test_and_set())
                {
                    _callback(websocket_event::connection_error, error_message);
                }

                disconnect();

                return;
            }

            _http_target_string = impl::http_encode_target({}, _uri_path, query_string);

            websocket_stream.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
            
            websocket_stream.set_option(boost::beast::websocket::stream_base::decorator(
                [this]
                (boost::beast::websocket::request_type& websocket_request)
                    {
                        websocket_request.set(boost::beast::http::field::user_agent, user_agent());
                    }));
            
            websocket_stream.async_handshake(_http_host_string, _http_target_string,
                [this, &websocket_stream, websocket_receive_timeout_seconds, websocket_send_timeout_seconds, timeout_seconds, timeout_flag, callback_flag]
                (boost::beast::error_code ec)
                    {
                        if (ec || timeout_flag->test())
                        {
                            if (!callback_flag->test_and_set())
                            {
                                _callback(websocket_event::connection_error, cpp_http_format::format("error on websocket handshake [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));
                            }

                            disconnect();
                            
                            return;
                        }

                        try
                        {
                            _timer.cancel();
                        }
                        catch (std::exception const&)
                        {
                        }

                        if (!callback_flag->test_and_set())
                        {
                            _callback(websocket_event::connection_succeeded, cpp_http_format::format("websocket connection established to [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));
                            
                            _websocket_receive_timeout_seconds = websocket_send_timeout_seconds.has_value() ? websocket_send_timeout_seconds.value_or(0) : _default_timeout_seconds.value_or(0);
                            _websocket_send_timeout_seconds = websocket_send_timeout_seconds.has_value() ? websocket_send_timeout_seconds.value_or(0) : _default_timeout_seconds.value_or(0);

                            _websocket_receive_timestamp = {};
                            _websocket_send_timestamp = {};

                            if (_websocket_receive_timeout_seconds || _websocket_send_timeout_seconds)
                            {
                                _websocket_receive_timestamp =
                                _websocket_send_timestamp = cpp_http_timeout_clock_type::now();

                                _timer.expires_from_now(boost::posix_time::seconds(1));
                                _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                                    [this]
                                    (boost::system::error_code ec)
                                        {
                                            boost::ignore_unused(ec);

                                            auto now = cpp_http_timeout_clock_type::now();

                                            if (_websocket_receive_timeout_seconds && (_websocket_receive_timestamp != cpp_http_timeout_time_point_type{}))
                                            {
                                                auto last_receive_seconds_interval = std::chrono::duration_cast<std::chrono::seconds>(now - _websocket_receive_timestamp).count();

                                                if (last_receive_seconds_interval >= _websocket_receive_timeout_seconds)
                                                {
                                                    _websocket_receive_timestamp = {};

                                                    _callback(websocket_event::receive_timed_out, cpp_http_format::format("websocket receive timed out from [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));

                                                    disconnect();

                                                    _callback(websocket_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));

                                                    return;
                                                }
                                            }

                                            if (send_queue_size() && _websocket_send_timeout_seconds && (_websocket_send_timestamp != cpp_http_timeout_time_point_type{}))
                                            {
                                                auto last_send_seconds_interval = std::chrono::duration_cast<std::chrono::seconds>(now - _websocket_send_timestamp).count();

                                                if (last_send_seconds_interval >= _websocket_send_timeout_seconds)
                                                {
                                                    _websocket_send_timestamp = {};
                                                    
                                                    _callback(websocket_event::send_timed_out, cpp_http_format::format("websocket send timed out from [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));

                                                    return;
                                                }
                                            }
                                        }));
                            }
                        }

                        do_websocket_receive(websocket_stream, _http_host_string, _http_target_string);
                    });
        }

        size_t send_queue_size()
        {
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            return _websocket_high_priority_send_queue.size() + _websocket_send_queue.size();
        }

        void on_send_complete(boost::beast::error_code ec)
        {
            if (ec)
            {
                _callback(websocket_event::send_error, cpp_http_format::format("error on websocket send: {}", _http_host_string, _http_target_string, ec.message()));
                
                disconnect();

                _callback(websocket_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));
                
                return;
            }

            _websocket_send_timestamp = cpp_http_timeout_clock_type::now();

            _callback(websocket_event::message_sent, _websocket_sending_message);

            auto lock = std::unique_lock(_websocket_send_queue_mutex);
            
            do_send_message_async(lock);
        }

        template <typename websocket_stream_type>
        void do_send(websocket_stream_type& websocket_stream)
        {
            websocket_stream.async_write(boost::asio::buffer(_websocket_sending_message), boost::asio::bind_executor(_strand, 
                [this]
                (boost::beast::error_code ec, size_t bytes_transferred)
                    {
                        boost::ignore_unused(bytes_transferred);

                        on_send_complete(ec);
                    }));
        }

        template <typename lock_type>
        void do_send_message_async(lock_type& lock)
        {
            auto sending = _websocket_send_busy.test_and_set();

            if (sending)
            {
                lock.unlock();

                return;
            }

            if (!_websocket_high_priority_send_queue.empty())
            {
                _websocket_sending_message = std::move(_websocket_high_priority_send_queue.front());
                _websocket_high_priority_send_queue.pop_front();
            }
            else if (!_websocket_send_queue.empty())
            {
                _websocket_sending_message = std::move(_websocket_send_queue.front());
                _websocket_send_queue.pop_front();
            }
            else
            {
                _websocket_sending_message.clear();
                _websocket_send_busy.clear();

                return;
            }

            lock.unlock();

            _websocket_send_timestamp = cpp_http_timeout_clock_type::now();

            if (_uri_protocol_is_secure)
            {
                do_send(_wss_stream);
            }
            else
            {
                do_send(_ws_stream);
            }
        }

    public:
        websocket_client() = delete;
        
        websocket_client(websocket_client const&) = delete;
        websocket_client(websocket_client&&) = delete;

        websocket_client& operator = (websocket_client const&) = delete;
        websocket_client& operator = (websocket_client&&) = delete;

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<size_t> default_timeout_seconds)
            : http_client_base(ioc, uri_protocol_is_secure, "ws", uri_host, uri_port, uri_path, default_timeout_seconds), _callback(callback), _ws_stream(ioc), _wss_stream(ioc, _ssl)
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, uri_port, uri_path, {})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<size_t> default_timeout_seconds)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_seconds)
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), {})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<size_t> default_timeout_seconds)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_seconds)
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), {})
        {
        }

        void connect_and_run(std::optional<size_t> connection_timeout_seconds = {}, std::optional<size_t> websocket_receive_timeout_seconds = {}, std::optional<size_t> websocket_send_timeout_seconds = {})
        {
            return connect_and_run(http_query_string {}, connection_timeout_seconds, websocket_receive_timeout_seconds, websocket_send_timeout_seconds);
        }

        void connect_and_run(http_query_string query_string, std::optional<size_t> connection_timeout_seconds = {}, std::optional<size_t> websocket_receive_timeout_seconds = {}, std::optional<size_t> websocket_send_timeout_seconds = {})
        {
            auto timeout_seconds = connection_timeout_seconds.has_value() ? connection_timeout_seconds.value_or(0) : _default_timeout_seconds.value_or(0);
            auto callback_called = std::make_shared<cpp_http_atomic_flag>(false);
            auto connection_timed_out = std::make_shared<cpp_http_atomic_flag>(false);
            
            if (timeout_seconds)
            {
                _timer.expires_from_now(boost::posix_time::seconds(timeout_seconds));
                _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                    [this, connection_timed_out, callback_called]
                    (boost::system::error_code ec)
                        {
                            boost::ignore_unused(ec);

                            if (!callback_called->test_and_set())
                            {
                                connection_timed_out->test_and_set();

                                disconnect();

                                _callback(websocket_event::connection_error, cpp_http_format::format("connection to {}:{} timed out", _uri_host, _uri_port_resolve));
                            }
                        }));
            }

            connect_async(
                [this, query_string, websocket_receive_timeout_seconds, websocket_send_timeout_seconds, timeout_seconds, connection_timed_out, callback_called]
                (std::string_view const error_message)
                    {
                        if (_uri_protocol_is_secure)
                        {
                            do_websocket_handshake(error_message, query_string, _wss_stream, connection_timed_out, callback_called, websocket_receive_timeout_seconds, websocket_send_timeout_seconds, timeout_seconds);
                        }
                        else
                        {
                            do_websocket_handshake(error_message, query_string, _ws_stream, connection_timed_out, callback_called, websocket_receive_timeout_seconds, websocket_send_timeout_seconds, timeout_seconds);
                        }
                    });
        }
        
        template <typename... Args>
        void send_message_async(Args&&... args)
        {
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            _websocket_send_queue.emplace_back(std::forward<Args>(args) ...);

            do_send_message_async(lock);
        }
        
        template <typename... Args>
        void send_high_priority_message_async(Args&&... args)
        {
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            _websocket_high_priority_send_queue.emplace_back(std::forward<Args>(args) ...);

            do_send_message_async(lock);
        }

    public:
        using shared_ptr = std::shared_ptr<websocket_client>;
    };
}
