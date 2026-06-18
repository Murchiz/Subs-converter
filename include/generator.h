#pragma once
#include "types.h"
#include <string>
#include <vector>

std::string gen_clash(const std::vector<Proxy>& proxies);
std::string gen_singbox(const std::vector<Proxy>& proxies);
std::string gen_v2ray(const std::vector<Proxy>& proxies);
