#include "utils.h"
#include "types.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <charconv>
#include <format>
#include <array>
#include <algorithm>

namespace {

constexpr auto make_base64_decode_table() {
    std::array<int8_t, 256> table{};
    table.fill(-1);
    constexpr std::string_view chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < chars.size(); ++i) {
        table[static_cast<unsigned char>(chars[i])] = static_cast<int8_t>(i);
    }
    table[static_cast<unsigned char>('-')] = 62;
    table[static_cast<unsigned char>('_')] = 63;
    return table;
}

constexpr auto B64_DECODE_TABLE = make_base64_decode_table();
constexpr std::string_view B64_ENCODE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string utf16_to_utf8(uint32_t cp) {
    std::string out;
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return out;
}

} // namespace

std::string base64_decode(std::string_view in) {
    std::string out;
    out.reserve(in.size() * 3 / 4);
    int val = 0;
    int valb = -8;
    for (char c : in) {
        int8_t d = B64_DECODE_TABLE[static_cast<unsigned char>(c)];
        if (d == -1) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::string url_decode(std::string_view str) {
    std::string ret;
    ret.reserve(str.size());
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%') {
            if (i + 2 < str.length()) {
                unsigned int v = 0;
                auto [ptr, ec] = std::from_chars(str.data() + i + 1, str.data() + i + 3, v, 16);
                if (ec == std::errc{}) {
                    ret += static_cast<char>(v);
                    i += 2;
                } else {
                    ret += str[i];
                }
            } else {
                ret += str[i];
            }
        } else if (str[i] == '+') {
            ret += ' ';
        } else {
            ret += str[i];
        }
    }
    return ret;
}

std::string base64_encode(std::string_view in) {
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    int val = 0;
    int valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(B64_ENCODE_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(B64_ENCODE_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

std::string url_encode(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.length() * 3 / 2);
    for (char c : value) {
        auto uc = static_cast<unsigned char>(c);
        if (std::isalnum(uc) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped += c;
        } else {
            escaped += std::format("%{:02X}", uc);
        }
    }
    return escaped;
}

std::string decode_json_string(std::string_view str) {
    std::string res;
    res.reserve(str.length());
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '\\' && i + 1 < str.length()) {
            char next = str[i + 1];
            if (next == '"') { res += '"'; i++; }
            else if (next == '\\') { res += '\\'; i++; }
            else if (next == '/') { res += '/'; i++; }
            else if (next == 'b') { res += '\b'; i++; }
            else if (next == 'f') { res += '\f'; i++; }
            else if (next == 'n') { res += '\n'; i++; }
            else if (next == 'r') { res += '\r'; i++; }
            else if (next == 't') { res += '\t'; i++; }
            else if (next == 'u' && i + 5 < str.length()) {
                uint32_t cp = 0;
                auto [ptr, ec] = std::from_chars(str.data() + i + 2, str.data() + i + 6, cp, 16);
                if (ec == std::errc{}) {
                    i += 5;
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 < str.length() && str[i + 1] == '\\' && str[i + 2] == 'u') {
                        uint32_t low = 0;
                        auto [ptr2, ec2] = std::from_chars(str.data() + i + 3, str.data() + i + 7, low, 16);
                        if (ec2 == std::errc{} && low >= 0xDC00 && low <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            i += 6;
                        }
                    }
                    res += utf16_to_utf8(cp);
                } else {
                    res += '\\';
                }
            } else {
                res += '\\';
            }
        } else {
            res += str[i];
        }
    }
    return res;
}

std::string json_extract_string(std::string_view json, std::string_view key) {
    std::string pattern = std::format("\"{}\"", key);
    size_t pos = json.find(pattern);
    if (pos == std::string_view::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string_view::npos) return "";
    size_t quote1 = json.find('"', pos);
    if (quote1 == std::string_view::npos) return "";
    size_t quote2 = json.find('"', quote1 + 1);
    if (quote2 != std::string_view::npos) {
        return decode_json_string(json.substr(quote1 + 1, quote2 - quote1 - 1));
    }
    return "";
}

int json_extract_int(std::string_view json, std::string_view key) {
    std::string pattern = std::format("\"{}\"", key);
    size_t pos = json.find(pattern);
    if (pos == std::string_view::npos) return 0;
    pos = json.find(':', pos);
    if (pos == std::string_view::npos) return 0;
    size_t num_start = json.find_first_of("0123456789-", pos);
    if (num_start != std::string_view::npos) {
        int val = 0;
        auto [ptr, ec] = std::from_chars(json.data() + num_start, json.data() + json.size(), val);
        if (ec == std::errc{}) {
            return val;
        }
    }
    return 0;
}

std::string sanitize_json(std::string_view str) {
    std::string res;
    res.reserve(str.length() + str.length() / 4);
    for (char c : str) {
        if (c == '"') res += "\\\"";
        else if (c == '\\') res += "\\\\";
        else if (c == '\n') res += "\\n";
        else if (c == '\r') res += "\\r";
        else if (c == '\t') res += "\\t";
        else res += c;
    }
    return res;
}

std::vector<std::string> json_extract_string_array(std::string_view json, std::string_view key) {
    std::vector<std::string> result;
    std::string pattern = std::format("\"{}\"", key);
    size_t pos = json.find(pattern);
    if (pos == std::string_view::npos) return result;
    pos = json.find(':', pos);
    if (pos == std::string_view::npos) return result;
    size_t b_start = json.find('[', pos);
    if (b_start == std::string_view::npos) return result;
    size_t b_end = json.find(']', b_start);
    if (b_end == std::string_view::npos) return result;

    std::string_view array_str = json.substr(b_start + 1, b_end - b_start - 1);
    size_t cur = 0;
    while (cur < array_str.length()) {
        size_t q1 = array_str.find('"', cur);
        if (q1 == std::string_view::npos) break;
        size_t q2 = array_str.find('"', q1 + 1);
        if (q2 == std::string_view::npos) break;
        std::string_view val = array_str.substr(q1 + 1, q2 - q1 - 1);
        result.push_back(decode_json_string(val));
        cur = q2 + 1;
    }
    return result;
}

