#pragma once
#include "types.h"
#include <string>
#include <vector>

Proxy parse_uri(const std::string& uri);
Proxy parse_xray_json(const std::string& obj);
std::vector<Proxy> parse_proxies(const std::string& decoded);
std::vector<Rule> parse_xray_rules(const std::string& json);

