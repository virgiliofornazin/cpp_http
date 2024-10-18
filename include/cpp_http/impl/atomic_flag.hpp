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
