/*
cpp_http library version 1.0.2

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

#include "config.hpp"

namespace cpp_http
{
    namespace impl
    {
        template <typename duration_type>
        static inline std::optional<std::chrono::milliseconds> optional_duration_cast_to_milliseconds(std::optional<duration_type> const& optional_duration)
        {
            if (optional_duration.has_value())
            {
                return std::chrono::duration_cast<std::chrono::milliseconds>(*optional_duration);
            }

            return {};
        }

        template <typename base_type>
        inline std::shared_ptr<base_type> shared_from_base_type(std::enable_shared_from_this<base_type>* base) 
        {
            return base->shared_from_this();
        }

        template <typename base_type>
        inline std::shared_ptr<const base_type> shared_from_base_type(std::enable_shared_from_this<base_type> const* base) 
        {
            return base->shared_from_this();
        }

        template <typename returning_type, typename current_type>
        inline std::shared_ptr<returning_type> shared_from(current_type* current) 
        {
            return std::dynamic_pointer_cast<returning_type>(shared_from_base_type(current));
        }

        template <typename current_type>
        inline std::shared_ptr<current_type> shared_from(current_type* current) 
        {
            return std::dynamic_pointer_cast<current_type>(shared_from_base_type(current));
        }

        template <typename base_type>
        inline std::weak_ptr<base_type> weak_from_base_type(std::enable_shared_from_this<base_type>* base) 
        {
            return base->weak_from_this();
        }

        template <typename base_type>
        inline std::weak_ptr<const base_type> weak_from_base_type(std::enable_shared_from_this<base_type> const* base) 
        {
            return base->weak_from_this();
        }

        template <typename returning_type, typename current_type>
        inline std::weak_ptr<returning_type> weak_from(current_type* current) 
        {
            return std::dynamic_pointer_cast<returning_type>(weak_from_base_type(current).lock());
        }

        template <typename current_type>
        inline std::weak_ptr<current_type> weak_from(current_type* current) 
        {
            return std::dynamic_pointer_cast<current_type>(weak_from_base_type(current).lock());
        }
    }
}
