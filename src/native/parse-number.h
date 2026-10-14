// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <optional>
#include <string_view>

namespace wgps {
// Range-checked parsing that never throws, for records read from disk and for arguments: anything but
// plain digits, or a value above maximum, is rejected rather than truncated or raised as an exception.
inline std::optional<unsigned long long> parseDecimal(std::string_view text, unsigned long long maximum) {
    if (text.empty()) return std::nullopt;
    unsigned long long value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        const unsigned long long digit = static_cast<unsigned long long>(c - '0');
        if (digit > maximum || value > (maximum - digit) / 10) return std::nullopt;
        value = value * 10 + digit;
    }
    return value;
}

// One hexadecimal digit's value, or -1.
inline int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace wgps
