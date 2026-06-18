#include "utils.h"
#include "types.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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

std::string json_extract_string(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    size_t quote1 = json.find("\"", pos);
    size_t quote2 = json.find("\"", quote1 + 1);
    if (quote1 != std::string::npos && quote2 != std::string::npos) {
        return json.substr(quote1 + 1, quote2 - quote1 - 1);
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
