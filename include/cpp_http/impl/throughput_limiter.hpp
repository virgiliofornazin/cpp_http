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
            size_t _interval_seconds = 0;
            size_t _throughput_limit_per_interval = 0;
            size_t _current_interval_throughput = 0;
            cpp_http_timeout_time_point_type _current_interval_started_at;
            size_t _total_throughput = 0;

        private:
            bool do_test_and(bool const set_if_true)
            {
                if (!is_throughput_limit_per_interval_set())
                {
                    ++_total_throughput;

                    return false;
                }

                auto now = cpp_http_timeout_clock_type::now();
                auto current_interval_seconds = static_cast<size_t>(std::chrono::duration_cast<std::chrono::seconds>(now - _current_interval_started_at).count());
                auto result = (current_interval_seconds != _interval_seconds);

                if (result)
                {
                    if (set_if_true)
                    {
                        clear();
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
                auto current_interval_seconds = static_cast<size_t>(std::chrono::duration_cast<std::chrono::seconds>(now - _current_interval_started_at).count());

                if (current_interval_seconds != _interval_seconds)
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

            explicit throughput_limiter(size_t const throughput_limit_per_interval, size_t const interval_seconds = 1)
                : _interval_seconds(interval_seconds), _throughput_limit_per_interval(throughput_limit_per_interval)
            {
            }

            void set_throughput_limit_per_interval(size_t const throughput_limit_per_interval, size_t const interval_seconds = 1, bool const clear_counters = false, bool const reset_total = false)
            {
                _interval_seconds = interval_seconds;
                _throughput_limit_per_interval = throughput_limit_per_interval;

                if (clear_counters)
                {
                    clear(reset_total);
                }
            }

            void reset_throughput_limit_per_interval(bool const reset_total = false)
            {
                _interval_seconds = 0;
                _throughput_limit_per_interval = 0;

                clear(reset_total);
            }

            void clear(bool const reset_total = false)
            {
                _current_interval_throughput = 0;
                _current_interval_started_at = {};

                if (reset_total)
                {
                    _total_throughput = 0;
                }
            }

            bool is_throughput_limit_per_interval_set() const noexcept
            {
                return (_interval_seconds && _throughput_limit_per_interval);
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
