#pragma once
#include <string>
#include <vector>

std::string base64_decode(const std::string &in);
std::string url_decode(const std::string& str);
std::string json_extract_string(const std::string& json, const std::string& key);
int json_extract_int(const std::string& json, const std::string& key);
std::string sanitize_json(const std::string& str);
