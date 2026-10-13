#pragma once
#include "types.h"
#include <string>
#include <string_view>
#include <vector>
#include <array>

std::string gen_clash(const std::vector<Proxy>& proxies, const std::vector<Rule>& rules = {}, const std::vector<Balancer>& balancers = {}, bool force_balancer = false);
std::string gen_singbox(const std::vector<Proxy>& proxies, std::string_view platform = "", const std::vector<Rule>& rules = {}, const std::vector<Balancer>& balancers = {}, bool force_balancer = false);
std::string gen_v2ray(const std::vector<Proxy>& proxies);
std::string gen_xray(const std::vector<Proxy>& proxies, std::string_view remarks = "", const std::vector<Rule>& rules = {});
std::string gen_xray_jsons(const std::vector<Proxy>& proxies, const std::vector<Balancer>& balancers = {}, const std::vector<Rule>& rules = {});

inline constexpr std::array<std::string_view, 11> supported_targets{
    "clash", "singbox-android", "sing-box-android", "singbox-pc", "sing-box-pc",
    "xray", "v2ray", "xray-one", "xray-json", "v2ray-json", "xray-jsons"
};

constexpr bool is_supported_target(std::string_view target) noexcept {
    for (const auto candidate : supported_targets) {
        if (candidate == target) return true;
    }
    return false;
}
