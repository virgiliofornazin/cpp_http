/*
cpp_http library version 1.0.6

Copyright (c) 2024, Virgilio Alexandre Fornazin

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#include "impl/config.hpp"
#include "impl/diagnostics.inl"

namespace cpp_http
{
    class interval_throughput_limiter
    {
    private:
        std::chrono::milliseconds _interval_milliseconds;
        size_t _throughput_limit_per_interval = 0;
        cpp_http::timeout_time_point _current_interval_started_at;
        size_t _current_interval_throughput = 0;
        size_t _total_throughput = 0;

    private:
        void do_clear(cpp_http::timeout_time_point const current_interval_started_at, bool const reset_total)
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

            auto now = cpp_http::timeout_clock::now();
            auto current_interval = std::chrono::duration_cast<std::chrono::milliseconds>(now - _current_interval_started_at);
            auto outside_throttle_interval = _interval_milliseconds.count() < current_interval.count();

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "interval_throughput_limiter::do_test_and[" << this << "] -> current_interval: " 
                << current_interval.count() << ", _interval_milliseconds: " << _interval_milliseconds.count(); return ss.str(); });

            auto result = false;

            if (outside_throttle_interval)
            {
                if (set_if_true)
                {
                    do_clear(now, false);
                }

                result = true;
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

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "interval_throughput_limiter::do_test_and[" << this << "] -> _total_throughput: " 
                << _total_throughput << ", _current_interval_throughput: " << _current_interval_throughput; return ss.str(); });

            return !result;
        }

        void do_unset()
        {
            if (!is_throughput_limit_per_interval_set())
            {
                return;
            }

            auto now = cpp_http::timeout_clock::now();
            auto current_interval = std::chrono::duration_cast<std::chrono::milliseconds>(now - _current_interval_started_at);
            auto outside_throttle_interval = _interval_milliseconds.count() < current_interval.count();

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "interval_throughput_limiter::do_pop[" << this << "] -> current_interval: " 
                << current_interval.count() << ", _interval_milliseconds: " << _interval_milliseconds.count(); return ss.str(); });

            if (outside_throttle_interval)
            {
                _current_interval_throughput = 0;
                
                return;
            }

            if (_current_interval_throughput > 0)
            {
                --_current_interval_throughput;
            }

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "interval_throughput_limiter::do_pop[" << this << "] -> _total_throughput: " 
                << _total_throughput << ", _current_interval_throughput: " << _current_interval_throughput; return ss.str(); });
        }

        void do_fill()
        {
            if (!is_throughput_limit_per_interval_set())
            {
                return;
            }

            auto now = cpp_http::timeout_clock::now();
            auto current_interval = std::chrono::duration_cast<std::chrono::milliseconds>(now - _current_interval_started_at);
            auto outside_throttle_interval = _interval_milliseconds.count() < current_interval.count();

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "interval_throughput_limiter::do_fill[" << this << "] -> current_interval: " 
                << current_interval.count() << ", _interval_milliseconds: " << _interval_milliseconds.count(); return ss.str(); });
            
            if (outside_throttle_interval)
            {
                _current_interval_started_at = now;
            }

            _current_interval_throughput = _throughput_limit_per_interval;

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "interval_throughput_limiter::do_fill[" << this << "] -> _total_throughput: " 
                << _total_throughput << ", _current_interval_throughput: " << _current_interval_throughput; return ss.str(); });
        }
    
    public:
        interval_throughput_limiter() = default;
        
        interval_throughput_limiter(interval_throughput_limiter const&) = default;
        interval_throughput_limiter(interval_throughput_limiter&&) = default;

        interval_throughput_limiter& operator = (interval_throughput_limiter const&) = default;
        interval_throughput_limiter& operator = (interval_throughput_limiter&&) = default;

        template <typename duration_type>
        explicit interval_throughput_limiter(size_t const throughput_limit_per_interval, duration_type const interval = std::chrono::duration_cast<duration_type>(std::chrono::seconds(1)))
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
            return (_interval_milliseconds.count() > 0) && (_throughput_limit_per_interval > 0);
        }

        bool test()
        {
            return do_test_and(false);
        }

        bool test_and_set()
        {
            return do_test_and(true);
        }

        void unset()
        {
            do_unset();
        }

        void fill()
        {
            do_fill();
        }
    };
}
