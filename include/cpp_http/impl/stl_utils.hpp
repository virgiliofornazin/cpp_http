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
    }
}
