#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <span>

std::string base64_decode(std::string_view in);
std::string base64_encode(std::string_view in);
std::string url_decode(std::string_view str);
#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <span>

std::string base64_decode(std::string_view in);
std::string base64_encode(std::string_view in);
std::string url_decode(std::string_view str);
std::string url_encode(std::string_view str);
std::string json_extract_string(std::string_view json, std::string_view key);
int json_extract_int(std::string_view json, std::string_view key);
std::string sanitize_json(std::string_view str);
std::string decode_json_string(std::string_view str);
std::vector<std::string> json_extract_string_array(std::string_view json, std::string_view key);
#include <cstdlib>

inline void* mem_alloc(size_t sz) {
    return std::malloc(sz);
}

inline void mem_free(void* ptr) {
    std::free(ptr);
}
