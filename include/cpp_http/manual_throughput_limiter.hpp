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
    class manual_throughput_limiter
    {
    protected:
        size_t _throughput_limit_per_interval = 0;
        size_t _current_interval_throughput = 0;
        size_t _total_throughput = 0;

    private:
        void do_clear(bool const reset_total)
        {                
            _current_interval_throughput = 0;

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

            auto result = _current_interval_throughput < _throughput_limit_per_interval;

            if (result)
            {
                ++_total_throughput;

                if (set_if_true)
                {
                    ++_current_interval_throughput;
                }
            }

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "manual_throughput_limiter::do_test_and[" << this << "] -> _total_throughput: " 
                << _total_throughput << ", _current_interval_throughput: " << _current_interval_throughput; return ss.str(); });

            return !result;
        }

        void do_unset()
        {
            if (!is_throughput_limit_per_interval_set())
            {
                return;
            }

            if (_current_interval_throughput > 0)
            {
                --_current_interval_throughput;
            }

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "manual_throughput_limiter::do_unset[" << this << "] -> _total_throughput: " 
                << _total_throughput << ", _current_interval_throughput: " << _current_interval_throughput; return ss.str(); });
        }

        void do_fill()
        {
            if (!is_throughput_limit_per_interval_set())
            {
                return;
            }

            _current_interval_throughput = _throughput_limit_per_interval;

            cpp_hpp_diagnostic_trace([&]() { std::stringstream ss; ss << "manual_throughput_limiter::do_fill[" << this << "] -> _total_throughput: " 
                << _total_throughput << ", _current_interval_throughput: " << _current_interval_throughput; return ss.str(); });
        }
    
    public:
        manual_throughput_limiter() = default;
        
        manual_throughput_limiter(manual_throughput_limiter const&) = default;
        manual_throughput_limiter(manual_throughput_limiter&&) = default;

        manual_throughput_limiter& operator = (manual_throughput_limiter const&) = default;
        manual_throughput_limiter& operator = (manual_throughput_limiter&&) = default;

        explicit manual_throughput_limiter(size_t const throughput_limit_per_interval, size_t const current_interval_throughput)
            : _throughput_limit_per_interval(throughput_limit_per_interval), _current_interval_throughput(current_interval_throughput)
        {
        }

        explicit manual_throughput_limiter(size_t const throughput_limit_per_interval)
            : _throughput_limit_per_interval(throughput_limit_per_interval)
        {
        }
        
        void set_throughput_limit_manually_per_interval(size_t const throughput_limit_per_interval,
            size_t const current_interval_throughput, bool const reset_total = false)
        {
            set_throughput_limit_per_interval(throughput_limit_per_interval, false, true);
            
            _current_interval_throughput = current_interval_throughput;
        }

        void set_throughput_limit_per_interval(size_t const throughput_limit_per_interval,
            bool const clear_counters = false, bool const reset_total = false)
        {
            _throughput_limit_per_interval = throughput_limit_per_interval;

            if (clear_counters)
            {
                clear(reset_total);
            }
        }

        void reset_throughput_limit_per_interval(bool const reset_total = false)
        {
            _throughput_limit_per_interval = 0;

            clear(reset_total);
        }

        void clear(bool const reset_total = false)
        {
            do_clear(reset_total);
        }

        bool is_throughput_limit_per_interval_set() const noexcept
        {
            return (_throughput_limit_per_interval > 0);
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
