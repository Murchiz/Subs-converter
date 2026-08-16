#pragma once
#include "types.h"
#include <string>
#include <string_view>
#include <vector>
#include <span>

std::string gen_clash(const std::vector<Proxy>& proxies, const std::vector<Rule>& rules = {});
std::string gen_singbox(const std::vector<Proxy>& proxies, std::string_view platform = "", const std::vector<Rule>& rules = {});
std::string gen_v2ray(const std::vector<Proxy>& proxies);
std::string gen_xray(const std::vector<Proxy>& proxies, std::string_view remarks = "", const std::vector<Rule>& rules = {});

