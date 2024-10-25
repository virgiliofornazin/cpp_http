/*
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

#include <atomic>

namespace cpp_http
{
    namespace impl
    {
        class atomic_flag
        {
        private:
            std::atomic_uint _flag;

        public:
            atomic_flag() noexcept = default;
            
            atomic_flag(atomic_flag const&) = delete;
            atomic_flag(atomic_flag&&) = delete;
            
            atomic_flag& operator = (atomic_flag const&) = delete;
            atomic_flag& operator = (atomic_flag&&) = delete;

            explicit atomic_flag(bool const value) noexcept
                : _flag(value ? 1 : 0)
            {
            }

            ~atomic_flag() noexcept = default;

            void clear(std::memory_order const order = std::memory_order_seq_cst) volatile noexcept
            {
                _flag.store(0, order);
            }

            void clear(std::memory_order const order = std::memory_order_seq_cst) noexcept
            {
                _flag.store(0, order);
            }

            bool test_and_set(std::memory_order const order = std::memory_order_seq_cst) volatile noexcept
            {
                return _flag.fetch_add(1, order) > 0;
            }

            bool test_and_set(std::memory_order const order = std::memory_order_seq_cst) noexcept
            {
                return _flag.fetch_add(1, order) > 0;
            }

            bool test(std::memory_order const order = std::memory_order_seq_cst) volatile noexcept
            {
                return _flag.load(order) > 0;
            }

            bool test(std::memory_order const order = std::memory_order_seq_cst) noexcept
            {
                return _flag.load(order) > 0;
            }
        };
    }
}
