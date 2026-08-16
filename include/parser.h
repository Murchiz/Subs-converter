#pragma once
#include "types.h"
#include <string>
#include <string_view>
#include <vector>

Proxy parse_uri(std::string_view uri);
Proxy parse_xray_json(std::string_view obj);
std::vector<Proxy> parse_clash_yaml(std::string_view yaml);
std::vector<Rule> parse_clash_rules(std::string_view yaml);
std::vector<Proxy> parse_proxies(std::string_view decoded);
std::vector<Rule> parse_xray_rules(std::string_view json);

