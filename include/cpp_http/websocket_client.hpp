#pragma once

#include "impl/config.hpp"
#include "impl/http_client_base.hpp"
#include "impl/throughput_limiter.hpp"
#include "http_query_string.hpp"
#include "impl/stl_headers.hpp"
#include "websocket_message.hpp"
#include "websocket_client_event.hpp"
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <array>
#include <chrono>
#include <mutex>
#include <numeric>

namespace cpp_http
{    
    class websocket_client
        : public impl::http_client_base
    {
    public:
        using event_callback = std::function<void(websocket_client_event const, std::string_view const)>;
        using authentication_request_message_generator = std::function<std::string()>;
        using authentication_response_message_handler = std::function<bool(std::string_view const)>;
        using heartbeat_request_message_generator = std::function<std::string()>;

    protected:
        boost::beast::websocket::stream<boost::beast::tcp_stream> _ws_stream;
        boost::beast::websocket::stream<cpp_http_asio::ssl::stream<boost::beast::tcp_stream>> _wss_stream;
        std::chrono::milliseconds _websocket_receive_timeout_interval = {};
        cpp_http_timeout_time_point_type _websocket_receive_timestamp;
        std::chrono::milliseconds _websocket_send_timeout_interval = {};
        cpp_http_timeout_time_point_type _websocket_send_timestamp;
        cpp_http_timeout_time_point_type _websocket_send_initiated_timestamp;
        websocket_message _websocket_send_pending_message;
        cpp_http_atomic_flag _websocket_send_in_progress;
        cpp_http_atomic_flag _websocket_send_queued_allowed;
        std::mutex _websocket_send_queue_mutex;
#ifdef CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
        std::array<std::deque<websocket_message>, websocket_message_priority_count> _websocket_send_queues;
        std::array<impl::throughput_limiter, websocket_message_priority_count> _websocket_send_queue_throughput_limiters;
#endif /* CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES */
#ifdef CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
        std::priority_queue<websocket_message> _websocket_send_queue;
        impl::throughput_limiter _websocket_send_queue_throughput_limiter;
#endif /* CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES */
        event_callback _callback;
        bool _authenticated = false;
        authentication_request_message_generator _authentication_request_message_generator;
        authentication_response_message_handler _authentication_response_message_handler;
        cpp_http_timeout_time_point_type _heartbeat_timestamp;
        std::chrono::milliseconds _heartbeat_interval = {};
        heartbeat_request_message_generator _heartbeat_request_message_generator;

    protected:
        virtual boost::beast::tcp_stream* beast_tcp_stream() override
        {
            return std::addressof(_uri_protocol_is_secure ? boost::beast::get_lowest_layer(_wss_stream) : boost::beast::get_lowest_layer(_ws_stream));
        }

        virtual cpp_http_asio::ssl::stream<boost::beast::tcp_stream>* asio_ssl_stream() override
        {
            return std::addressof(_wss_stream.next_layer());
        }
        
        bool has_authentication_handlers()
        {
            return _authentication_request_message_generator && _authentication_response_message_handler;
        }
        
        bool has_heartbeat_handlers()
        {
            return (_heartbeat_interval.count() > 0) && _heartbeat_request_message_generator;
        }

        template <typename connection_timeout_duration_type, typename receive_timeout_duration_type, typename send_timeout_duration_type>
        void do_start_async(http_query_string& query_string, std::optional<connection_timeout_duration_type> const& connection_timeout_interval, 
            std::optional<receive_timeout_duration_type> const& websocket_receive_timeout_interval, std::optional<send_timeout_duration_type> const& websocket_send_timeout_interval)
        {
            disable_send_queued_messages();

            auto timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(connection_timeout_interval.has_value() ?
                connection_timeout_interval.value_or(connection_timeout_duration_type{}) : _default_timeout_interval.value_or(std::chrono::milliseconds{}));

            auto callback_called = std::make_shared<cpp_http_atomic_flag>(false);
            auto connection_timed_out = std::make_shared<cpp_http_atomic_flag>(false);
            
            if (timeout_interval.count() > 0)
            {
                _strand.post(
                    [this, connection_timed_out, callback_called, timeout_interval]
                    ()
                        {
                            _timer.expires_from_now(boost::posix_time::milliseconds(timeout_interval.count()));
                            _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                                [this, connection_timed_out, callback_called]
                                (boost::system::error_code ec) mutable
                                    {
                                        CPP_HTTP_TRACE([&]() { std::stringstream ss; ss << "_timer.expired(start), ec: " << ec; return ss.str(); });

                                        if (ec)
                                        {
                                            return;
                                        }

                                        auto should_callback = !callback_called->test_and_set();

                                        if (should_callback)
                                        {
                                            connection_timed_out->test_and_set();

                                            disconnect();

                                            _callback(websocket_client_event::connection_error, cpp_http_format::format("connection to {}:{} timed out", _uri_host, _uri_port_resolve));
                                        }
                                    }));
                        });
            }

            do_connect_async(callback_called, connection_timed_out, cpp_http_asio::bind_executor(_strand, 
                [this, query_string, websocket_receive_timeout_interval, websocket_send_timeout_interval, connection_timed_out, callback_called]
                (std::string_view const error_message) mutable
                    {
                        if (_uri_protocol_is_secure)
                        {
                            do_websocket_handshake(error_message, query_string, _wss_stream, websocket_receive_timeout_interval, websocket_send_timeout_interval, connection_timed_out, callback_called);
                        }
                        else
                        {
                            do_websocket_handshake(error_message, query_string, _ws_stream, websocket_receive_timeout_interval, websocket_send_timeout_interval, connection_timed_out, callback_called);
                        }
                    }));
        }
    
        template <typename websocket_stream_type>
        void do_websocket_receive(websocket_stream_type& websocket_stream)
        {
            websocket_stream.async_read(_flat_buffer, cpp_http_asio::bind_executor(_strand, 
                [this, &websocket_stream]
                (boost::beast::error_code ec, size_t bytes_transferred) mutable
                    {
                        CPP_HTTP_TRACE([&]() { std::stringstream ss; ss << "websocket_stream.async_read(), ec: " << ec; return ss.str(); });

                        boost::ignore_unused(bytes_transferred);

                        if (ec)
                        {
                            _callback(websocket_client_event::receive_error, cpp_http_format::format("websocket receive error from [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));
                            
                            disconnect();

                            _callback(websocket_client_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));

                            return;
                        }

                        if (!websocket_stream.got_text())
                        {
                            _callback(websocket_client_event::receive_error, cpp_http_format::format("websocket receive no data from [{}{}]", _http_host_string, _http_target_string));
                            
                            disconnect();

                            _callback(websocket_client_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]", _http_host_string, _http_target_string));

                            return;
                        }

                        _websocket_receive_timestamp = cpp_http_timeout_clock_type::now();

                        auto message_received = boost::beast::buffers_to_string(_flat_buffer.data());

                        _flat_buffer.consume(_flat_buffer.size());

                        _callback(websocket_client_event::message_received, message_received);

                        if (!_authenticated)
                        {
                            if (has_authentication_handlers())
                            {
                                auto authentication_result = _authentication_response_message_handler(message_received);

                                if (!authentication_result)
                                {
                                    _callback(websocket_client_event::authentication_error, cpp_http_format::format("websocket authentication error to [{}{}], authentication resoponse validation failed", _http_host_string, _http_target_string));

                                    disconnect();

                                    _callback(websocket_client_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]", _http_host_string, _http_target_string));
                                }
                                else
                                {
                                    on_websocket_authenticated(", authentication resoponse validation succeeded");
                                }
                            }
                        }
                        
                        if (_authenticated)
                        {    
                            do_websocket_receive(websocket_stream);
                        }                        
                    }));
        }

        template <typename websocket_stream_type, typename atomic_flag_type, typename receive_timeout_duration_type, typename send_timeout_duration_type>
        void do_websocket_handshake(std::string_view const error_message, http_query_string query_string, websocket_stream_type& websocket_stream, std::optional<receive_timeout_duration_type> const& websocket_receive_timeout_interval, std::optional<send_timeout_duration_type> const& websocket_send_timeout_interval, atomic_flag_type& timeout_flag, atomic_flag_type& callback_called)
        {
            _connected = false;
            
            if (!error_message.empty() || timeout_flag->test())
            {
                auto should_callback = !callback_called->test_and_set();

                if (should_callback)
                {
                    _callback(websocket_client_event::connection_error, error_message);
                }

                disconnect();

                return;
            }

            _http_target_string = impl::http_encode_uri_target({}, _uri_path, query_string);

            websocket_stream.set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
            
            websocket_stream.set_option(boost::beast::websocket::stream_base::decorator(
                [this]
                (boost::beast::websocket::request_type& websocket_request) mutable
                    {
                        websocket_request.set(boost::beast::http::field::user_agent, user_agent());
                    }));
            
            websocket_stream.async_handshake(_http_host_string, _http_target_string, cpp_http_asio::bind_executor(_strand,
                [this, &websocket_stream, websocket_receive_timeout_interval, websocket_send_timeout_interval, timeout_flag, callback_called]
                (boost::beast::error_code ec) mutable
                    {
                        CPP_HTTP_TRACE([&]() { std::stringstream ss; ss << "websocket_stream::async_handshake(), ec: " << ec; return ss.str(); });

                        auto should_callback = !callback_called->test_and_set();

                        if (ec || timeout_flag->test())
                        {
                            if (should_callback)
                            {
                                _callback(websocket_client_event::connection_error, cpp_http_format::format("error on websocket handshake [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));
                            }

                            disconnect();
                            
                            return;
                        }

                        if (!_connection_in_progress)
                        {
                            return;
                        }

                        _connected = true;
                        _connection_in_progress = !_connected;

                        _callback(websocket_client_event::connection_succeeded, cpp_http_format::format("websocket connection established to [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));

                        auto authentication_needed = false;

                        if (has_authentication_handlers())
                        {
                            auto authentication_request_message = _authentication_request_message_generator();

                            if (!authentication_request_message.empty())
                            {
                                authentication_needed = true;

                                _websocket_send_pending_message = websocket_message(std::move(authentication_request_message));
                                
                                do_send_pending_message(false);
                            }
                        }

                        if (!authentication_needed)
                        {
                            _websocket_send_initiated_timestamp = {};
                        }

                        do_initialize_watchdog_timer(websocket_receive_timeout_interval, websocket_send_timeout_interval);

                        if (!authentication_needed)
                        {
                            on_websocket_authenticated(" bacause no custom authentication handler was specified");
                        }

                        do_websocket_receive(websocket_stream);
                    }));
        }
        
        void on_websocket_authenticated(std::string_view const reason = {})
        {
            _authenticated = true;

            _callback(websocket_client_event::authentication_succeeded, cpp_http_format::format("websocket connection assumed authenticated to [{}{}]{}", _http_host_string, _http_target_string, reason));

            send_queued_messages(true);
        }

        template <typename receive_timeout_duration_type, typename send_timeout_duration_type>
        void do_initialize_watchdog_timer(std::optional<receive_timeout_duration_type> const& websocket_receive_timeout_interval, std::optional<send_timeout_duration_type> const& websocket_send_timeout_interval)
        {
            _websocket_receive_timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(websocket_receive_timeout_interval.has_value() ?
                websocket_receive_timeout_interval.value_or(receive_timeout_duration_type{}) : _default_timeout_interval.value_or(std::chrono::milliseconds{}));

            _websocket_send_timeout_interval = std::chrono::duration_cast<std::chrono::milliseconds>(websocket_send_timeout_interval.has_value() ?
                websocket_send_timeout_interval.value_or(send_timeout_duration_type{}) : _default_timeout_interval.value_or(std::chrono::milliseconds{}));
            
            _websocket_receive_timestamp = {};
            _websocket_send_timestamp = {};
            _heartbeat_timestamp = {};

            if ((_websocket_receive_timeout_interval.count() > 0) || (_websocket_send_timeout_interval.count() > 0) || (_heartbeat_interval.count() > 0))
            {
                auto now = cpp_http_timeout_clock_type::now();
                
                _websocket_receive_timestamp = now;

                do_cancel_timer();
                do_watchdog_timer(std::chrono::milliseconds(25));
            }
        }

        void do_watchdog_timer(std::chrono::milliseconds const& watchdog_timer_interval)
        {
            if (_connected)
            {
                _strand.post(
                    [this, watchdog_timer_interval]
                    ()
                        {
                            _timer.expires_from_now(boost::posix_time::milliseconds(watchdog_timer_interval.count()));
                            _timer.async_wait(cpp_http_asio::bind_executor(_strand, 
                                [this, watchdog_timer_interval]
                                (boost::system::error_code ec) mutable
                                    {
                                        /* CPP_HTTP_TRACE([&]() { std::stringstream ss; ss << "_timer.async_wait(watchdog), ec: " << ec; return ss.str(); }); */

                                        if (ec)
                                        {
                                            return;
                                        }

                                        auto now = cpp_http_timeout_clock_type::now();

                                        if (_websocket_receive_timeout_interval.count() > 0)
                                        {
                                            auto last_receive_interval = std::chrono::duration_cast<std::chrono::milliseconds>(now - _websocket_receive_timestamp);

                                            if (_websocket_receive_timeout_interval.count() < last_receive_interval.count())
                                            {
                                                _callback(websocket_client_event::receive_timed_out, cpp_http_format::format("websocket receive timed out from [{}{}]", _http_host_string, _http_target_string));

                                                disconnect();

                                                _callback(websocket_client_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]", _http_host_string, _http_target_string));

                                                return;
                                            }
                                        }

                                        if ((_websocket_send_initiated_timestamp.time_since_epoch().count() > 0) && (_websocket_send_timeout_interval.count() > 0))
                                        {
                                            auto last_send_initiated_interval = std::chrono::duration_cast<std::chrono::seconds>(now - _websocket_send_initiated_timestamp);

                                            if ((_websocket_send_initiated_timestamp.time_since_epoch().count() > 0) && (_websocket_send_timeout_interval.count() < last_send_initiated_interval.count()))
                                            {
                                                _callback(websocket_client_event::send_timed_out, cpp_http_format::format("websocket send timed out from [{}{}]", _http_host_string, _http_target_string));

                                                disconnect();

                                                _callback(websocket_client_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]", _http_host_string, _http_target_string));

                                                return;
                                            }
                                        }

                                        auto sent_heartbeat = false;

                                        if (has_heartbeat_handlers())
                                        {
                                            auto last_heartbeat_considered_timestamp = std::max(std::max(_websocket_receive_timestamp, _websocket_send_timestamp), _heartbeat_timestamp);
                                            auto last_heartbeat_operation_interval = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_heartbeat_considered_timestamp);

                                            if (_heartbeat_interval.count() < last_heartbeat_operation_interval.count())
                                            {
                                                auto heartbeat_request_message = _heartbeat_request_message_generator();

                                                if (!heartbeat_request_message.empty())
                                                {
                                                    _heartbeat_timestamp = now;

                                                    send_message_with_priority_async(websocket_message_priority::lowest, heartbeat_request_message);

                                                    sent_heartbeat = true;
                                                }
                                            }
                                        }

                                        if (!sent_heartbeat)
                                        {
                                            send_queued_messages();
                                        }

                                        do_watchdog_timer(watchdog_timer_interval);
                                    }));
                        });
            }
        }

        template <typename websocket_stream_type>
        void do_websocket_send(websocket_stream_type& websocket_stream, bool send_queued_after_complete)
        {
            _websocket_send_initiated_timestamp = cpp_http_timeout_clock_type::now();

            websocket_stream.async_write(cpp_http_asio::buffer(_websocket_send_pending_message.ref()), cpp_http_asio::bind_executor(_strand, 
                [this, send_queued_after_complete]
                (boost::beast::error_code ec, size_t bytes_transferred) mutable
                    {
                        CPP_HTTP_TRACE([&]() { std::stringstream ss; ss << "websocket_stream.async_write(), ec: " << ec; return ss.str(); });

                        boost::ignore_unused(bytes_transferred);

                        if (ec)
                        {
                            _callback(websocket_client_event::send_error, cpp_http_format::format("error on websocket send: {}", _http_host_string, _http_target_string, ec.message()));
                            
                            disconnect();

                            _callback(websocket_client_event::disconnection, cpp_http_format::format("websocket disconnected from [{}{}]: {}", _http_host_string, _http_target_string, ec.message()));
                            
                            return;
                        }

                        _websocket_send_initiated_timestamp = {};
                        _websocket_send_timestamp = cpp_http_timeout_clock_type::now();
                        
                        auto sent_message_body = _websocket_send_pending_message.detach();

                        _websocket_send_pending_message.clear();
                        _websocket_send_in_progress.clear();

                        _callback(websocket_client_event::message_sent, sent_message_body);

                        if (send_queued_after_complete)
                        {
                            send_queued_messages();
                        }
                    }));
        }

        template <typename queue_type>
        std::optional<websocket_message> do_get_next_pending_message_from_queue(queue_type& queue, impl::throughput_limiter& limit)
        {
            if (queue.empty())
            {
                return {};
            }

            auto throttle = limit.test_and_set();

            if (throttle)
            {
                return {};
            }

            auto result = std::move(queue.front());

            queue.pop_front();

            return result;
        }

#ifdef CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
        std::optional<websocket_message> get_next_pending_message_from_queue(websocket_message_priority const priority_queue)
        {
            auto const priority_queue_index = static_cast<size_t>(priority_queue);

            auto& websocket_send_queue = _websocket_send_queues.at(priority_queue_index);
            auto& websocket_send_queue_throughput_limiter = _websocket_send_queue_throughput_limiters.at(priority_queue_index);

            return do_get_next_pending_message_from_queue(websocket_send_queue, websocket_send_queue_throughput_limiter); 
        }

        std::optional<websocket_message> get_next_pending_message_from_queues()
        {
            std::optional<websocket_message> result;

            for (size_t priority_queue_index = 0; priority_queue_index < websocket_message_priority_count; ++priority_queue_index)
            {
                result = get_next_pending_message_from_queue(static_cast<websocket_message_priority>(priority_queue_index));

                if (result)
                {
                    break;
                }
            }
            
            return result;
        }
#endif /* CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES */

#ifdef CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
        std::optional<websocket_message> get_next_pending_message_from_queue(websocket_message_priority const)
        {
            return do_get_next_pending_message_from_queue(_websocket_send_queue, _websocket_send_queue_throughput_limiter);
        }
        
        std::optional<websocket_message> get_next_pending_message_from_queues()
        {
            return do_get_next_pending_message_from_queue(_websocket_send_queue, _websocket_send_queue_throughput_limiter);
        }
#endif /* CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES */

        template <typename unique_lock_type>
        void do_send_queued_messages(unique_lock_type& lock)
        {
            auto send_queued_allowed = _websocket_send_queued_allowed.test();

            {
                std::lock_guard guard(lock, std::adopt_lock);

                if (!send_queued_allowed)
                {
                    return;
                }

                auto send_in_progress = _websocket_send_in_progress.test_and_set();

                if (send_in_progress)
                {
                    return;
                }

                auto pending_message = get_next_pending_message_from_queues();
                
                if (!pending_message)
                {
                    _websocket_send_pending_message.clear();
                    _websocket_send_in_progress.clear();

                    return;
                }

                _websocket_send_pending_message = std::move(*pending_message);
            }

            do_send_pending_message(send_queued_allowed);
        }

        void do_send_pending_message(bool const send_queued_allowed)
        {
            if (_uri_protocol_is_secure)
            {
                do_websocket_send(_wss_stream, send_queued_allowed);
            }
            else
            {
                do_websocket_send(_ws_stream, send_queued_allowed);
            }
        }

    public:
        websocket_client() = delete;
        
        websocket_client(websocket_client const&) = delete;
        websocket_client(websocket_client&&) = delete;

        websocket_client& operator = (websocket_client const&) = delete;
        websocket_client& operator = (websocket_client&&) = delete;

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
            : http_client_base(ioc, sslc, uri_protocol_is_secure, "ws", uri_host, uri_port, uri_path, default_timeout_interval), _ws_stream(cpp_http_asio::make_strand(ioc)), _wss_stream(cpp_http_asio::make_strand(ioc), _sslc), _callback(callback)
        {
            _assume_connected_on_transport_connection_succeeded = false;
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
            : http_client_base(ioc, uri_protocol_is_secure, "ws", uri_host, uri_port, uri_path, default_timeout_interval), _ws_stream(cpp_http_asio::make_strand(ioc)), _wss_stream(cpp_http_asio::make_strand(ioc), _sslc), _callback(callback)
        {
            _assume_connected_on_transport_connection_succeeded = false;
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, sslc, {}, uri_protocol_is_secure, uri_host, uri_port, uri_path, default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, {}, uri_protocol_is_secure, uri_host, uri_port, uri_path, default_timeout_interval)
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
            : websocket_client(ioc, sslc, callback, uri_protocol_is_secure, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
            : websocket_client(ioc, sslc, {}, uri_protocol_is_secure, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::string_view const uri_path)
            : websocket_client(ioc, {}, uri_protocol_is_secure, uri_host, uri_port, uri_path, std::optional<std::chrono::milliseconds>{})
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, sslc, callback, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, sslc, {}, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, {}, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), default_timeout_interval)
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
            : websocket_client(ioc, sslc, callback, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
            : websocket_client(ioc, sslc, {}, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::string_view const uri_port)
            : websocket_client(ioc, {}, uri_protocol_is_secure, uri_host, uri_port, std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, sslc, callback, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, sslc, {}, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
        {
        }

        template <typename duration_type>
        explicit websocket_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host, std::optional<duration_type> default_timeout_interval)
            : websocket_client(ioc, {}, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), default_timeout_interval)
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host)
            : websocket_client(ioc, sslc, callback, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, event_callback callback, bool const uri_protocol_is_secure, std::string_view const uri_host)
            : websocket_client(ioc, callback, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, cpp_http_asio::ssl::context& sslc, bool const uri_protocol_is_secure, std::string_view const uri_host)
            : websocket_client(ioc, sslc, {}, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        explicit websocket_client(cpp_http_asio::io_context& ioc, bool const uri_protocol_is_secure, std::string_view const uri_host)
            : websocket_client(ioc, {}, uri_protocol_is_secure, uri_host, std::string_view(), std::string_view(), std::optional<std::chrono::milliseconds>{})
        {
        }

        bool authenticated() const noexcept
        {
            return _authenticated;
        }

        void set_message_authentication_handler(authentication_request_message_generator request_message_generator, authentication_response_message_handler response_message_handler)
        {
            throw_if_connected();

            _authentication_request_message_generator = request_message_generator;
            _authentication_response_message_handler = response_message_handler;
        }

        void reset_message_authentication_handler()
        {
            throw_if_connected();

            _authentication_request_message_generator = {};
            _authentication_response_message_handler = {};
        }

        template <typename duration_type>
        void set_message_heartbeat_handler(duration_type const& heartbeat_interval, heartbeat_request_message_generator request_message_generator)
        {
            throw_if_connected();

            _heartbeat_interval = std::chrono::duration_cast<std::chrono::milliseconds>(heartbeat_interval);
            _heartbeat_request_message_generator = request_message_generator;
        }

        void reset_message_heartbeat_handler()
        {
            throw_if_connected();

            _heartbeat_interval = {};
            _heartbeat_request_message_generator = {};
        }
        
#ifdef CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
        size_t send_queue_size()
        {
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            size_t result = 0;

            for (auto& queue: _websocket_send_queues)
            {
                result += queue.size();
            }
            
            return result;    
        }

        void clear_send_queues()
        {
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            for (auto& queue: _websocket_send_queues)
            {
                queue.clear();
            }
        }
        
        void clear_send_queue(websocket_message_priority const priority)
        {
            auto const priority_queue_index = static_cast<size_t>(priority);

            auto& websocket_send_queue = _websocket_send_queues.at(priority_queue_index);
            
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            websocket_send_queue.clear();
        }
        
        template <typename duration_type>
        void set_send_queue_throughput_limit_per_interval(websocket_message_priority const priority, size_t const throughput, duration_type const interval, bool const clear_counters = false)
        {
            auto const priority_queue_index = static_cast<size_t>(priority);

            auto& websocket_send_queue_throughput_limiter = _websocket_send_queue_throughput_limiters.at(priority_queue_index);
            
            websocket_send_queue_throughput_limiter.set_throughput_limit_per_interval(throughput, interval, clear_counters);
        }

        auto& send_queue_throughput_limiter(websocket_message_priority const priority)
        {
            auto const priority_queue_index = static_cast<size_t>(priority);

            auto& websocket_send_queue_throughput_limiter = _websocket_send_queue_throughput_limiters.at(priority_queue_index);
            
            return websocket_send_queue_throughput_limiter;
        }

        auto const& send_queue_throughput_limiter(websocket_message_priority const priority) const
        {
            auto const priority_queue_index = static_cast<size_t>(priority);

            auto& websocket_send_queue_throughput_limiter = _websocket_send_queue_throughput_limiters.at(priority_queue_index);
            
            return websocket_send_queue_throughput_limiter;
        }

        std::priority_queue<websocket_message> extract_queued_messages()
        {
            std::priority_queue<websocket_message> result;

            for (auto& queue: _websocket_send_queues)
            {
                for (auto& message: queue)
                {
                    result.emplace(std::move(message));
                }
            }
            
            return result;
        }
#endif /* CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES */

#ifdef CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
        size_t send_queue_size()
        {
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            return _websocket_send_queue.size();
        }

        void clear_send_queues()
        {
            clear_send_queue();
        }

        void clear_send_queue()
        {
            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            _websocket_send_queue = {};
        }

        template <typename duration_type>
        void set_send_queue_throughput_limit_per_interval(size_t const throughput, duration_type const interval, bool const clear_counters = false)
        {
            _websocket_send_queue_throughput_limiter.set_throughput_limit_per_interval(throughput, interval, clear_counters);
        }

        auto& send_queue_throughput_limiter() noexcept
        {
            return _websocket_send_queue_throughput_limiter;
        }

        auto const& send_queue_throughput_limiter() const noexcept
        {
            return _websocket_send_queue_throughput_limiter;
        }

        std::priority_queue<websocket_message> extract_queued_messages()
        {
            return std::move(_websocket_send_queue);
        }
#endif /* CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES */

        template <typename connection_timeout_duration_type = std::chrono::milliseconds, typename receive_timeout_duration_type = std::chrono::milliseconds, typename send_timeout_duration_type = std::chrono::milliseconds>
        void start_async(event_callback callback, std::optional<connection_timeout_duration_type> connection_timeout_interval = {}, std::optional<receive_timeout_duration_type> websocket_receive_timeout_interval = {}, std::optional<send_timeout_duration_type> websocket_send_timeout_interval = {})
        {
            _callback = callback;

            return start_async(http_query_string {}, connection_timeout_interval, websocket_receive_timeout_interval, websocket_send_timeout_interval);
        }

        template <typename connection_timeout_duration_type = std::chrono::milliseconds, typename receive_timeout_duration_type = std::chrono::milliseconds, typename send_timeout_duration_type = std::chrono::milliseconds>
        void start_async(event_callback callback, http_query_string query_string, std::optional<connection_timeout_duration_type> connection_timeout_interval = {}, std::optional<receive_timeout_duration_type> websocket_receive_timeout_interval = {}, std::optional<send_timeout_duration_type> websocket_send_timeout_interval = {})
        {
            _callback = callback;
            
            return start_async(query_string, connection_timeout_interval, websocket_receive_timeout_interval, websocket_send_timeout_interval);
        }

        template <typename connection_timeout_duration_type = std::chrono::milliseconds, typename receive_timeout_duration_type = std::chrono::milliseconds, typename send_timeout_duration_type = std::chrono::milliseconds>
        void start_async(std::optional<connection_timeout_duration_type> connection_timeout_interval = {}, std::optional<receive_timeout_duration_type> websocket_receive_timeout_interval = {}, std::optional<send_timeout_duration_type> websocket_send_timeout_interval = {})
        {
            return start_async(http_query_string {}, connection_timeout_interval, websocket_receive_timeout_interval, websocket_send_timeout_interval);
        }

        template <typename connection_timeout_duration_type = std::chrono::milliseconds, typename receive_timeout_duration_type = std::chrono::milliseconds, typename send_timeout_duration_type = std::chrono::milliseconds>
        void start_async(http_query_string query_string, std::optional<connection_timeout_duration_type> connection_timeout_interval = {}, std::optional<receive_timeout_duration_type> websocket_receive_timeout_interval = {}, std::optional<send_timeout_duration_type> websocket_send_timeout_interval = {})
        {
            do_start_async(query_string, connection_timeout_interval, websocket_receive_timeout_interval, websocket_send_timeout_interval);
        }

        template <typename... Args>
        void send_message_with_priority_async(websocket_message_priority const priority, Args&&... args)
        {
            websocket_message pending_message(priority, std::string(std::forward<Args>(args) ...));

            auto lock = std::unique_lock(_websocket_send_queue_mutex);

#ifdef CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES
            auto const priority_queue_index = static_cast<size_t>(priority);

            auto& websocket_send_queue = _websocket_send_queues.at(priority_queue_index);

            websocket_send_queue.emplace_back(std::move(pending_message));
#endif /* CPP_HTTP_WEBSOCKET_SEPARATED_PRIORITY_SEND_QUEUES */

#ifdef CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES
            _websocket_send_queue.emplace_back(std::move(pending_message));
#endif /* CPP_HTTP_WEBSOCKET_UNIQUE_PRIORITY_SEND_QUEUES */

            do_send_queued_messages(lock);
        }

        template <typename... Args>
        void send_message_async(Args&&... args)
        {
            send_message_with_priority_async(websocket_message_priority::normal, std::forward<Args>(args) ...);
        }

        void enable_send_queued_messages()
        {
            _websocket_send_queued_allowed.test_and_set();
        }

        void disable_send_queued_messages()
        {
            _websocket_send_queued_allowed.clear();
        }

        bool send_queued_messages_allowed()
        {
            return _websocket_send_queued_allowed.test();
        }

        void send_queued_messages(bool const enable_send_queued_messages_if_disabled = false)
        {
            if (enable_send_queued_messages_if_disabled)
            {
                enable_send_queued_messages();
            }

            auto lock = std::unique_lock(_websocket_send_queue_mutex);

            do_send_queued_messages(lock);
        }

        virtual void disconnect() override
        {
            _authenticated = false;

            http_client_base::disconnect();
        }

    public:
        using shared_ptr = std::shared_ptr<websocket_client>;
    };
}
