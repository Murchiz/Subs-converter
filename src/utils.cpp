#include "utils.h"
#include "types.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

std::string base64_decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    T['-'] = 62; T['_'] = 63;
    int val = 0, valb = -8;
    for (char c : in) {
        if (T[(unsigned char)c] == -1) continue;
        val = (val << 6) + T[(unsigned char)c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::string url_decode(const std::string& str) {
    std::string ret;
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '%') {
            if (i + 2 < str.length()) {
                int v;
                sscanf(str.substr(i + 1, 2).c_str(), "%x", &v);
                ret += static_cast<char>(v);
                i += 2;
            }
        } else if (str[i] == '+') {
            ret += ' ';
        } else {
            ret += str[i];
        }
    }
    return ret;
}

std::string base64_encode(const std::string &in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string url_encode(const std::string &value) {
    std::string escaped;
    escaped.reserve(value.length());
    for (char c : value) {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped += c;
        } else {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c);
            escaped += buf;
        }
    }
    return escaped;
}

static std::string utf16_to_utf8(uint32_t cp) {
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

std::string decode_json_string(const std::string& str) {
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
                bool ok = true;
                for (int j = 0; j < 4; j++) {
                    char c = str[i + 2 + j];
                    cp <<= 4;
                    if (c >= '0' && c <= '9') cp += (c - '0');
                    else if (c >= 'a' && c <= 'f') cp += (c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') cp += (c - 'A' + 10);
                    else { ok = false; break; }
                }
                if (ok) {
                    i += 5;
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 < str.length() && str[i + 1] == '\\' && str[i + 2] == 'u') {
                        uint32_t low = 0;
                        bool low_ok = true;
                        for (int j = 0; j < 4; j++) {
                            char c = str[i + 3 + j];
                            low <<= 4;
                            if (c >= '0' && c <= '9') low += (c - '0');
                            else if (c >= 'a' && c <= 'f') low += (c - 'a' + 10);
                            else if (c >= 'A' && c <= 'F') low += (c - 'A' + 10);
                            else { low_ok = false; break; }
                        }
                        if (low_ok && low >= 0xDC00 && low <= 0xDFFF) {
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

std::string json_extract_string(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    size_t quote1 = json.find("\"", pos);
    size_t quote2 = json.find("\"", quote1 + 1);
    if (quote1 != std::string::npos && quote2 != std::string::npos) {
        return decode_json_string(json.substr(quote1 + 1, quote2 - quote1 - 1));
    }
    return "";
}

int json_extract_int(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return 0;
    pos = json.find(":", pos);
    size_t num_start = json.find_first_of("0123456789", pos);
    size_t num_end = json.find_first_not_of("0123456789", num_start);
    if (num_start != std::string::npos) {
        return std::stoi(json.substr(num_start, num_end - num_start));
    }
    return 0;
}

std::string sanitize_json(const std::string& str) {
    std::string res;
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

std::vector<std::string> json_extract_string_array(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return result;
    pos = json.find(":", pos);
    if (pos == std::string::npos) return result;
    size_t b_start = json.find("[", pos);
    if (b_start == std::string::npos) return result;
    size_t b_end = json.find("]", b_start);
    if (b_end == std::string::npos) return result;

    std::string array_str = json.substr(b_start + 1, b_end - b_start - 1);
    size_t cur = 0;
    while (cur < array_str.length()) {
        size_t q1 = array_str.find("\"", cur);
        if (q1 == std::string::npos) break;
        size_t q2 = array_str.find("\"", q1 + 1);
        if (q2 == std::string::npos) break;
        std::string val = array_str.substr(q1 + 1, q2 - q1 - 1);
        result.push_back(decode_json_string(val));
        cur = q2 + 1;
    }
    return result;
}

