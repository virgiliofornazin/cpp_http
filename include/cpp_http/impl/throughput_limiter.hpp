#pragma once

#include "config.hpp"
#include <optional>

namespace cpp_http
{
    namespace impl
    {
        class throughput_limiter
        {
        private:
            std::chrono::milliseconds _interval_milliseconds;
            size_t _throughput_limit_per_interval = 0;
            cpp_http_timeout_time_point_type _current_interval_started_at;
            size_t _current_interval_throughput = 0;
            size_t _total_throughput = 0;

        private:
            void do_clear(cpp_http_timeout_time_point_type const current_interval_started_at, bool const reset_total)
            {                
                _current_interval_throughput = 0;
                _current_interval_started_at = current_interval_started_at;

                if (reset_total)
                {
                    _total_throughput = 0;
                }
            }

            bool do_test_and(bool const set_if_true)
            {
                if (!is_throughput_limit_per_interval_set())
                {
                    ++_total_throughput;

                    return false;
                }

                auto now = cpp_http_timeout_clock_type::now();
                auto current_interval_seconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - _current_interval_started_at);
                auto result = _interval_milliseconds.count() < current_interval_seconds.count();

                if (result)
                {
                    if (set_if_true)
                    {
                        do_clear(now, false);
                    }
                }
                else
                {
                    result = _current_interval_throughput < _throughput_limit_per_interval;
                }

                if (result)
                {
                    ++_total_throughput;

                    if (set_if_true)
                    {
                        ++_current_interval_throughput;
                    }
                }

                return !result;
            }

            void do_fill()
            {
                if (!is_throughput_limit_per_interval_set())
                {
                    return;
                }

                auto now = cpp_http_timeout_clock_type::now();
                auto current_interval_seconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - _current_interval_started_at);
                auto result = _interval_milliseconds.count() < current_interval_seconds.count();
                
                if (result)
                {
                    _current_interval_started_at = now;
                }

                _current_interval_throughput = _throughput_limit_per_interval;
            }
        
        public:
            throughput_limiter() = default;
            
            throughput_limiter(throughput_limiter const&) = default;
            throughput_limiter(throughput_limiter&&) = default;

            throughput_limiter& operator = (throughput_limiter const&) = default;
            throughput_limiter& operator = (throughput_limiter&&) = default;

            template <typename duration_type>
            explicit throughput_limiter(size_t const throughput_limit_per_interval, duration_type const interval = std::chrono::duration_cast<duration_type>(std::chrono::seconds(1)))
                : _interval_milliseconds(std::chrono::duration_cast<std::chrono::milliseconds>(interval)), _throughput_limit_per_interval(throughput_limit_per_interval)
            {
            }

            template <typename duration_type>
            void set_throughput_limit_per_interval(size_t const throughput_limit_per_interval, duration_type const interval = std::chrono::duration_cast<duration_type>(std::chrono::seconds(1)), 
                bool const clear_counters = false, bool const reset_total = false)
            {
                _interval_milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(interval);
                _throughput_limit_per_interval = throughput_limit_per_interval;

                if (clear_counters)
                {
                    clear(reset_total);
                }
            }

            void reset_throughput_limit_per_interval(bool const reset_total = false)
            {
                _interval_milliseconds = std::chrono::milliseconds(1000);
                _throughput_limit_per_interval = 0;

                clear(reset_total);
            }

            void clear(bool const reset_total = false)
            {
                do_clear({}, reset_total);
            }

            bool is_throughput_limit_per_interval_set() const noexcept
            {
                return _throughput_limit_per_interval > 0;
            }

            bool test()
            {
                return do_test_and(false);
            }

            bool test_and_set()
            {
                return do_test_and(true);
            }

            void fill()
            {
                do_fill();
            }
        };
    }
}
