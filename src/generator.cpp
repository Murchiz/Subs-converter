#include "generator.h"
#include "utils.h"
#include <cstring>
#include <format>
#include <string_view>

std::string gen_clash(const std::vector<Proxy>& proxies, const std::vector<Rule>& rules, const std::vector<Balancer>& balancers, bool force_balancer) {
    std::string out = "mixed-port: 7890\n"
                      "socks-port: 7891\n"
                      "allow-lan: true\n"
                      "mode: rule\n"
                      "log-level: info\n"
                      "proxies:\n";
    std::string proxy_names;
    for (const auto& p : proxies) {
        if (!p.protocol[0]) continue;
        
        std::string s_name = sanitize_json(p.name);
        proxy_names += std::format("      - {}\n", s_name);
        
        out += std::format("  - name: {}\n"
                           "    type: {}\n"
                           "    server: {}\n"
                           "    port: {}\n",
                           s_name, p.protocol, p.server, p.port);

        std::string_view proto = p.protocol;
        if (proto == "vless" || proto == "vmess") {
            out += std::format("    uuid: {}\n", p.uuid);
            if (proto == "vmess") {
                out += "    alterId: 0\n"
                       "    cipher: auto\n";
            }
            if (proto == "vless") {
                out += "    udp: true\n"
                       "    packet-encoding: xudp\n";
                if (p.flow[0]) {
                    out += std::format("    flow: {}\n", p.flow);
                }
            }
        } else if (proto == "trojan") {
            out += std::format("    password: {}\n"
                               "    udp: true\n", p.uuid);
        } else if (proto == "hysteria2") {
            out += std::format("    password: {}\n", p.uuid);
            if (p.sni[0]) out += std::format("    sni: {}\n", p.sni);
            if (p.obfs[0]) out += std::format("    obfs: {}\n", p.obfs);
            if (p.obfs_pass[0]) out += std::format("    obfs-password: {}\n", p.obfs_pass);
            out += std::format("    up: {}\n"
                               "    down: {}\n"
                               "    skip-cert-verify: false\n",
                               p.up[0] ? p.up : "100 Mbps",
                               p.down[0] ? p.down : "100 Mbps");
        } else if (proto == "hysteria") {
            out += std::format("    auth_str: {}\n", p.uuid);
            if (p.sni[0]) out += std::format("    sni: {}\n", p.sni);
            if (p.obfs[0]) out += std::format("    obfs: {}\n", p.obfs);
            if (p.obfs_pass[0]) out += std::format("    obfs-parameter: {}\n", p.obfs_pass);
            out += std::format("    up: {}\n"
                               "    down: {}\n"
                               "    skip-cert-verify: false\n",
                               p.up[0] ? p.up : "100 Mbps",
                               p.down[0] ? p.down : "100 Mbps");
        }

        std::string net = p.type;
        if (net == "httpupgrade") net = "ws";
        if (proto != "hysteria2" && proto != "hysteria" && p.type[0]) {
            out += std::format("    network: {}\n", net);
        }

        std::string_view sec = p.security;
        if (sec == "tls" || sec == "reality") {
            out += "    tls: true\n";
            if (p.sni[0]) out += std::format("    servername: {}\n", p.sni);
            if (p.fp[0]) out += std::format("    client-fingerprint: {}\n", p.fp);
            if (p.alpn[0]) {
                out += "    alpn:\n";
                std::string_view alpn_str = p.alpn;
                size_t s = 0;
                while (s < alpn_str.length()) {
                    size_t c = alpn_str.find(',', s);
                    if (c == std::string_view::npos) c = alpn_str.length();
                    out += std::format("      - {}\n", alpn_str.substr(s, c - s));
                    s = c + 1;
                }
            }
        }

        if (sec == "reality") {
            out += std::format("    reality-opts:\n"
                               "      public-key: {}\n", p.pbk);
            if (p.sid[0]) out += std::format("      short-id: {}\n", p.sid);
        }

        std::string_view ptype = p.type;
        if (ptype == "ws") {
            const char* host_val = p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server);
            out += std::format("    ws-opts:\n"
                               "      path: \"{}\"\n"
                               "      headers:\n"
                               "        Host: {}\n",
                               p.path[0] ? p.path : "/", host_val);
        } else if (ptype == "grpc") {
            out += std::format("    grpc-opts:\n"
                               "      grpc-service-name: {}\n", p.path);
        } else if (ptype == "xhttp") {
            const char* host_val = p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server);
            out += std::format("    xhttp-opts:\n"
                               "      path: {}\n"
                               "      host: {}\n",
                               p.path[0] ? p.path : "/", host_val);
            if (p.mode[0]) out += std::format("      mode: {}\n", p.mode);
            if (p.extra[0]) out += std::format("      extra: {}\n", p.extra);
        } else if (ptype == "httpupgrade") {
            const char* host_val = p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server);
            out += std::format("    ws-opts:\n"
                               "      path: {}\n"
                               "      headers:\n"
                               "        Host: {}\n"
                               "      v2ray-http-upgrade: true\n"
                               "      v2ray-http-upgrade-fast-open: true\n",
                               p.path[0] ? p.path : "/", host_val);
        }
    }
    
    bool add_our = balancers.empty() || force_balancer;

    std::string groups = "proxy-groups:\n"
                         "  - name: Proxy\n"
                         "    type: select\n"
                         "    proxies:\n";
    if (add_our) {
        groups += "      - Auto\n";
    }
    for (const auto& b : balancers) {
        if (!b.proxies.empty()) {
            groups += std::format("      - {}\n", sanitize_json(b.name));
        }
    }
    groups += proxy_names;

    for (const auto& b : balancers) {
        if (b.proxies.empty()) continue;
        std::string b_type = b.type[0] ? b.type : "url-test";
        if (b_type == "urltest") b_type = "url-test";
        groups += std::format("  - name: {}\n"
                              "    type: {}\n", sanitize_json(b.name), b_type);
        if (b_type == "url-test") {
            groups += "    url: http://www.gstatic.com/generate_204\n"
                      "    interval: 300\n";
        }
        groups += "    proxies:\n";
        for (const auto& p_name : b.proxies) {
            groups += std::format("      - {}\n", sanitize_json(p_name));
        }
    }

    if (add_our) {
        groups += "  - name: Auto\n"
                  "    type: url-test\n"
                  "    url: http://www.gstatic.com/generate_204\n"
                  "    interval: 300\n"
                  "    proxies:\n" + proxy_names;
    }
    groups += "rules:\n";
    out += groups;

    std::string clash_rules;
    for (const auto& r : rules) {
        std::string target = "Proxy";
        std::string_view r_out = r.outbound;
        if (r_out == "direct") target = "DIRECT";
        else if (r_out == "block" || r_out == "reject") target = "REJECT";
        else if (r_out == "proxy" || r_out == "Proxy") target = "Proxy";
        else if (!r_out.empty()) target = r.outbound;

        for (const auto& dom : r.domains) {
            std::string_view d = dom;
            if (d.starts_with("domain:")) d = d.substr(7);
            if (d.starts_with("full:")) {
                clash_rules += std::format("  - DOMAIN,{},{}\n", d.substr(5), target);
            } else if (d.starts_with("geosite:")) {
                clash_rules += std::format("  - GEOSITE,{},{}\n", d.substr(8), target);
            } else if (!d.starts_with("regexp:")) {
                clash_rules += std::format("  - DOMAIN-SUFFIX,{},{}\n", d, target);
            }
        }
        for (const auto& ip : r.ips) {
            std::string_view i = ip;
            if (i == "geoip:private") {
                clash_rules += std::format("  - GEOIP,private,{},no-resolve\n", target);
            } else if (i.starts_with("geoip:")) {
                clash_rules += std::format("  - GEOIP,{},{},no-resolve\n", i.substr(6), target);
            } else {
                bool is_v6 = i.contains(':');
                if (!i.contains('/')) {
                    if (is_v6) clash_rules += std::format("  - IP-CIDR6,{}/128,{},no-resolve\n", i, target);
                    else clash_rules += std::format("  - IP-CIDR,{}/32,{},no-resolve\n", i, target);
                } else {
                    if (is_v6) clash_rules += std::format("  - IP-CIDR6,{},{},no-resolve\n", i, target);
                    else clash_rules += std::format("  - IP-CIDR,{},{},no-resolve\n", i, target);
                }
            }
        }
        if (!r.port.empty()) {
            clash_rules += std::format("  - DST-PORT,{},{}\n", r.port, target);
        }
    }
    clash_rules += "  - MATCH,Proxy\n";
    out += clash_rules;
    return out;
}

std::string gen_singbox(const std::vector<Proxy>& proxies, std::string_view platform, const std::vector<Rule>& rules, const std::vector<Balancer>& balancers, bool force_balancer) {
    std::string route_extra = ",\"auto_detect_interface\":true";
    if (platform == "android") {
        route_extra += ",\"override_android_vpn\":true";
    }

    struct SbRuleSet {
        std::string tag;
        std::string url;
    };
    std::vector<SbRuleSet> rule_sets;
    auto add_rule_set = [&](const std::string& tag, const std::string& url) {
        for (const auto& rs : rule_sets) {
            if (rs.tag == tag) return;
        }
        rule_sets.push_back({tag, url});
    };

    std::string sing_rules = "[{\"action\":\"sniff\"},{\"mode\":\"or\",\"type\":\"logical\",\"rules\":[{\"protocol\":\"dns\"},{\"port\":53}],\"action\":\"hijack-dns\"},{\"outbound\":\"direct\",\"ip_is_private\":true}";

    for (const auto& r : rules) {
        std::string target_out = "Proxy";
        std::string_view r_out = r.outbound;
        bool is_reject = (r_out == "block" || r_out == "reject");
        if (r_out == "direct") target_out = "direct";
        else if (r_out == "proxy" || r_out == "Proxy") target_out = "Proxy";
        else if (!r_out.empty()) target_out = r.outbound;

        if (!r.protocols.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += "\"protocol\":[";
            for (size_t k = 0; k < r.protocols.size(); k++) {
                if (k > 0) sing_rules += ",";
                sing_rules += std::format("\"{}\"", sanitize_json(r.protocols[k]));
            }
            sing_rules += "]}";
        }

        std::vector<std::string> domain_suffixes;
        std::vector<std::string> full_domains;
        std::vector<std::string> dom_rule_sets;

        for (const auto& dom : r.domains) {
            std::string_view d = dom;
            if (d.starts_with("geosite:")) {
                std::string tag = std::format("geosite-{}", d.substr(8));
                std::string url = std::format("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{}.srs", tag);
                add_rule_set(tag, url);
                dom_rule_sets.push_back(tag);
            } else if (d.starts_with("full:")) {
                full_domains.push_back(std::string(d.substr(5)));
            } else if (d.starts_with("domain:")) {
                domain_suffixes.push_back(std::string(d.substr(7)));
            } else if (!d.starts_with("regexp:")) {
                domain_suffixes.push_back(std::string(d));
            }
        }

        if (!domain_suffixes.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += "\"domain_suffix\":[";
            for (size_t k = 0; k < domain_suffixes.size(); k++) {
                if (k > 0) sing_rules += ",";
                sing_rules += std::format("\"{}\"", sanitize_json(domain_suffixes[k]));
            }
            sing_rules += "]}";
        }

        if (!full_domains.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += "\"domain\":[";
            for (size_t k = 0; k < full_domains.size(); k++) {
                if (k > 0) sing_rules += ",";
                sing_rules += std::format("\"{}\"", sanitize_json(full_domains[k]));
            }
            sing_rules += "]}";
        }

        if (!dom_rule_sets.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += "\"rule_set\":[";
            for (size_t k = 0; k < dom_rule_sets.size(); k++) {
                if (k > 0) sing_rules += ",";
                sing_rules += std::format("\"{}\"", sanitize_json(dom_rule_sets[k]));
            }
            sing_rules += "]}";
        }

        bool has_private_ip = false;
        std::vector<std::string> ip_rule_sets;
        std::vector<std::string> cidrs;

        for (const auto& ip : r.ips) {
            std::string_view i = ip;
            if (i == "geoip:private") {
                has_private_ip = true;
            } else if (i.starts_with("geoip:")) {
                std::string tag = std::format("geoip-{}", i.substr(6));
                std::string url = std::format("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{}.srs", tag);
                add_rule_set(tag, url);
                ip_rule_sets.push_back(tag);
            } else {
                std::string s(i);
                bool is_v6 = (s.find(':') != std::string::npos);
                if (s.find('/') == std::string::npos) {
                    if (is_v6) s += "/128";
                    else s += "/32";
                }
                cidrs.push_back(s);
            }
        }

        if (has_private_ip) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += "\"ip_is_private\":true}";
        }

        if (!ip_rule_sets.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += "\"rule_set\":[";
            for (size_t k = 0; k < ip_rule_sets.size(); k++) {
                if (k > 0) sing_rules += ",";
                sing_rules += std::format("\"{}\"", sanitize_json(ip_rule_sets[k]));
            }
            sing_rules += "]}";
        }

        if (!cidrs.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += "\"ip_cidr\":[";
            for (size_t k = 0; k < cidrs.size(); k++) {
                if (k > 0) sing_rules += ",";
                sing_rules += std::format("\"{}\"", sanitize_json(cidrs[k]));
            }
            sing_rules += "]}";
        }

        if (!r.port.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += std::format("\"outbound\":\"{}\",", target_out);
            sing_rules += std::format("\"port\":[{}]}}", r.port);
        }
    }
    sing_rules += "]";

    std::string rule_set_json;
    if (!rule_sets.empty()) {
        rule_set_json = ",\"rule_set\":[";
        for (size_t k = 0; k < rule_sets.size(); k++) {
            if (k > 0) rule_set_json += ",";
            rule_set_json += std::format("{{\"type\":\"remote\",\"tag\":\"{}\",\"format\":\"binary\",\"url\":\"{}\"}}",
                                         rule_sets[k].tag, rule_sets[k].url);
        }
        rule_set_json += "]";
    }

    std::string out = std::format("{{\n"
                                  "  \"dns\": {{\"strategy\":\"ipv4_only\",\"rules\":[{{\"server\":\"remote\",\"query_type\":[\"A\",\"AAAA\"]}}],\"servers\":[{{\"tag\":\"cf-dns\",\"type\":\"tls\",\"server\":\"1.1.1.1\"}},{{\"tag\":\"local\",\"type\":\"local\"}},{{\"tag\":\"remote\",\"type\":\"fakeip\",\"inet4_range\":\"198.18.0.0/15\",\"inet6_range\":\"fc00::/18\"}}]}},\n"
                                  "  \"http_clients\": [{{\"tag\":\"default\"}}],\n"
                                  "  \"log\": {{\"level\":\"info\",\"disabled\":false,\"timestamp\":true}},\n"
                                  "  \"route\": {{\"default_domain_resolver\":\"local\",\"default_http_client\":\"default\",\"rules\":{}{}{}}},\n"
                                  "  \"inbounds\": [{{\"mtu\":9000,\"tag\":\"tun-in\",\"type\":\"tun\",\"stack\":\"mixed\",\"auto_route\":true,\"strict_route\":true,\"address\":[\"172.19.0.1/30\",\"fdfe:dcba:9876::1/126\"],\"endpoint_independent_nat\":true}},{{\"tag\":\"mixed-in\",\"type\":\"mixed\",\"users\":[],\"listen\":\"127.0.0.1\",\"listen_port\":2412,\"set_system_proxy\":false}}],\n"
                                  "  \"outbounds\": [\n",
                                  sing_rules, route_extra, rule_set_json);
    std::string proxy_tags;
    std::string outbounds_arr;
    std::vector<std::string> valid_proxy_names;
    bool first = true;
    for (size_t i = 0; i < proxies.size(); i++) {
        const auto& p = proxies[i];
        if (!p.protocol[0]) continue;
        if (std::string_view(p.type) == "xhttp") continue; // Sing-box does not support xhttp
        
        std::string s_name = sanitize_json(p.name);
        valid_proxy_names.push_back(s_name);
        proxy_tags += std::format("\"{}\",", s_name);
        
        if (!first) outbounds_arr += ",\n";
        first = false;
        
        std::string sb_type = p.protocol;
        if (sb_type == "https") sb_type = "http";
        else if (sb_type == "ss") sb_type = "shadowsocks";
        else if (sb_type == "socks5") sb_type = "socks";
        else if (sb_type == "hy2") sb_type = "hysteria2";

        outbounds_arr += "    {\n";
        outbounds_arr += std::format("      \"type\": \"{}\",\n"
                                     "      \"tag\": \"{}\",\n"
                                     "      \"server\": \"{}\",\n"
                                     "      \"server_port\": {}",
                                     sb_type, s_name, p.server, p.port);

        std::string_view proto = p.protocol;
        if (proto == "vless" || proto == "vmess") {
            outbounds_arr += std::format(",\n      \"uuid\": \"{}\"", p.uuid);
            if (proto == "vmess") {
                outbounds_arr += ",\n      \"security\": \"auto\"";
            }
            if (proto == "vless" && p.flow[0]) {
                outbounds_arr += std::format(",\n      \"flow\": \"{}\"", p.flow);
            }
        } else if (proto == "trojan") {
            outbounds_arr += std::format(",\n      \"password\": \"{}\"", p.uuid);
        } else if (proto == "shadowsocks" || proto == "ss") {
            outbounds_arr += std::format(",\n      \"method\": \"{}\",\n      \"password\": \"{}\"",
                                         p.cipher[0] ? p.cipher : "aes-128-gcm", p.uuid);
        } else if (proto == "http" || proto == "https") {
            if (p.uuid[0]) {
                outbounds_arr += std::format(",\n      \"password\": \"{}\"", p.uuid);
            }
            if (proto == "https" || std::string_view(p.security) == "tls") {
                outbounds_arr += ",\n      \"tls\": {\n        \"enabled\": true";
                if (p.sni[0]) outbounds_arr += std::format(",\n        \"server_name\": \"{}\"", p.sni);
                outbounds_arr += "\n      }";
            }
        } else if (proto == "socks" || proto == "socks5") {
            outbounds_arr += ",\n      \"version\": \"5\"";
            if (p.uuid[0]) {
                outbounds_arr += std::format(",\n      \"password\": \"{}\"", p.uuid);
            }
        } else if (proto == "hysteria2" || proto == "hy2") {
            outbounds_arr += std::format(",\n      \"password\": \"{}\",\n      \"tls\": {{\n        \"enabled\": true", p.uuid);
            if (p.sni[0]) outbounds_arr += std::format(",\n        \"server_name\": \"{}\"", p.sni);
            outbounds_arr += "\n      }";
            if (p.obfs[0]) {
                outbounds_arr += std::format(",\n      \"obfs\": {{\n        \"type\": \"{}\"", p.obfs);
                if (p.obfs_pass[0]) outbounds_arr += std::format(",\n        \"password\": \"{}\"", p.obfs_pass);
                outbounds_arr += "\n      }";
            }
        } else if (proto == "hysteria") {
            outbounds_arr += std::format(",\n      \"auth_str\": \"{}\",\n      \"tls\": {{\n        \"enabled\": true", p.uuid);
            if (p.sni[0]) outbounds_arr += std::format(",\n        \"server_name\": \"{}\"", p.sni);
            outbounds_arr += "\n      }";
            if (p.obfs[0]) {
                outbounds_arr += std::format(",\n      \"obfs\": {{\n        \"type\": \"{}\"", p.obfs);
                if (p.obfs_pass[0]) outbounds_arr += std::format(",\n        \"password\": \"{}\"", p.obfs_pass);
                outbounds_arr += "\n      }";
            }
            if (p.up[0]) {
                int up_val = atoi(p.up);
                if (up_val > 0) outbounds_arr += std::format(",\n      \"up_mbps\": {}", up_val);
            }
            if (p.down[0]) {
                int down_val = atoi(p.down);
                if (down_val > 0) outbounds_arr += std::format(",\n      \"down_mbps\": {}", down_val);
            }
        }

        std::string_view sec = p.security;
        if (proto != "hysteria2" && proto != "hy2" && proto != "hysteria" && proto != "http" && proto != "https" && (sec == "tls" || sec == "reality")) {
            outbounds_arr += ",\n      \"tls\": {\n        \"enabled\": true";
            if (p.sni[0]) outbounds_arr += std::format(",\n        \"server_name\": \"{}\"", p.sni);
            if (p.fp[0]) outbounds_arr += std::format(",\n        \"utls\": {{ \"enabled\": true, \"fingerprint\": \"{}\" }}", p.fp);
            if (p.alpn[0]) {
                outbounds_arr += ",\n        \"alpn\": [";
                std::string_view alpn_str = p.alpn;
                size_t s = 0;
                bool first_alpn = true;
                while (s < alpn_str.length()) {
                    size_t c = alpn_str.find(',', s);
                    if (c == std::string_view::npos) c = alpn_str.length();
                    if (!first_alpn) outbounds_arr += ", ";
                    outbounds_arr += std::format("\"{}\"", alpn_str.substr(s, c - s));
                    first_alpn = false;
                    s = c + 1;
                }
                outbounds_arr += "]";
            }
            if (sec == "reality") {
                outbounds_arr += std::format(",\n        \"reality\": {{\n          \"enabled\": true,\n          \"public_key\": \"{}\"", p.pbk);
                if (p.sid[0]) outbounds_arr += std::format(",\n          \"short_id\": \"{}\"", p.sid);
                outbounds_arr += "\n        }";
            }
            outbounds_arr += "\n      }";
        }

        std::string_view ptype = p.type;
        if (proto != "hysteria2" && proto != "hy2" && proto != "hysteria" && p.type[0] && ptype != "tcp") {
            outbounds_arr += std::format(",\n      \"transport\": {{\n        \"type\": \"{}\"", p.type);
            if (ptype == "ws" || ptype == "httpupgrade" || ptype == "xhttp") {
                const char* host_val = p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server);
                outbounds_arr += std::format(",\n        \"path\": \"{}\",\n        \"headers\": {{ \"Host\": \"{}\" }}",
                                             p.path[0] ? p.path : "/", host_val);
                if (ptype == "xhttp" && p.extra[0]) {
                    outbounds_arr += std::format(",\n        \"extra\": {}", p.extra);
                }
            } else if (ptype == "grpc") {
                outbounds_arr += std::format(",\n        \"service_name\": \"{}\"", p.path);
            }
            outbounds_arr += "\n      }";
        }

        outbounds_arr += "\n    }";
    }
    
    bool add_our = balancers.empty() || force_balancer;

    std::string selector_outbounds;
    if (add_our && !valid_proxy_names.empty()) {
        selector_outbounds += "\"Auto\", ";
    }

    std::string balancer_outbounds;
    for (const auto& b : balancers) {
        std::vector<std::string> valid_b_proxies;
        for (const auto& pn : b.proxies) {
            for (const auto& vpn : valid_proxy_names) {
                if (vpn == pn) {
                    valid_b_proxies.push_back(pn);
                    break;
                }
            }
        }
        if (!valid_b_proxies.empty()) {
            selector_outbounds += std::format("\"{}\", ", sanitize_json(b.name));
            balancer_outbounds += "    {\n"
                                  "      \"type\": \"urltest\",\n"
                                  + std::format("      \"tag\": \"{}\",\n", sanitize_json(b.name))
                                  + "      \"outbounds\": [";
            for (size_t k = 0; k < valid_b_proxies.size(); k++) {
                if (k > 0) balancer_outbounds += ", ";
                balancer_outbounds += std::format("\"{}\"", sanitize_json(valid_b_proxies[k]));
            }
            balancer_outbounds += "]\n    },\n";
        }
    }

    for (const auto& vpn : valid_proxy_names) {
        selector_outbounds += std::format("\"{}\", ", vpn);
    }
    if (!selector_outbounds.empty() && selector_outbounds.ends_with(", ")) {
        selector_outbounds.resize(selector_outbounds.size() - 2);
    }

    if (!selector_outbounds.empty()) {
        out += std::format("    {{\n      \"type\": \"selector\",\n      \"tag\": \"Proxy\",\n      \"outbounds\": [{}]\n    }},\n",
                           selector_outbounds);
        if (!balancer_outbounds.empty()) {
            out += balancer_outbounds;
        }
        if (add_our && !valid_proxy_names.empty()) {
            std::string auto_members;
            for (size_t k = 0; k < valid_proxy_names.size(); k++) {
                if (k > 0) auto_members += ", ";
                auto_members += std::format("\"{}\"", valid_proxy_names[k]);
            }
            out += std::format("    {{\n      \"type\": \"urltest\",\n      \"tag\": \"Auto\",\n      \"outbounds\": [{}]\n    }},\n",
                               auto_members);
        }
    }

    out += "    {\n      \"tag\": \"direct\",\n      \"type\": \"direct\"\n    }";
    if (!outbounds_arr.empty()) {
        out += ",\n" + outbounds_arr;
    }
    out += "\n  ]\n}\n";
    return out;
}

static std::string format_xray_proxy_outbound(const Proxy& p, std::string_view tag, std::string_view indent = "    ") {
    std::string proto = p.protocol;
    if (proto == "hy2" || proto == "hysteria2" || proto == "hysteria") proto = "vless";

    std::string out = std::format("{}{{\n"
                                  "{}  \"tag\": \"{}\",\n"
                                  "{}  \"protocol\": \"{}\",\n", indent, indent, tag, indent, proto);

    if (proto == "vless" || proto == "vmess") {
        out += std::format("{}  \"settings\": {{\n"
                           "{}    \"vnext\": [\n"
                           "{}      {{\n"
                           "{}        \"address\": \"{}\",\n"
                           "{}        \"port\": {},\n"
                           "{}        \"users\": [\n"
                           "{}          {{\n"
                           "{}            \"id\": \"{}\"",
                           indent, indent, indent, indent, p.server, indent, p.port, indent, indent, indent, p.uuid);
        if (proto == "vless") {
            out += std::format(",\n{}            \"encryption\": \"none\"", indent);
            if (p.flow[0]) out += std::format(",\n{}            \"flow\": \"{}\"", indent, p.flow);
        } else if (proto == "vmess") {
            int alt = (p.alterId[0]) ? atoi(p.alterId) : 0;
            out += std::format(",\n{}            \"alterId\": {},\n{}            \"security\": \"{}\"",
                               indent, alt, indent, p.cipher[0] ? p.cipher : "auto");
        }
        out += std::format("\n{}          }}\n"
                           "{}        ]\n"
                           "{}      }}\n"
                           "{}    ]\n"
                           "{}  }}", indent, indent, indent, indent, indent);
    } else if (proto == "trojan") {
        out += std::format("{}  \"settings\": {{\n"
                           "{}    \"servers\": [\n"
                           "{}      {{\n"
                           "{}        \"address\": \"{}\",\n"
                           "{}        \"port\": {},\n"
                           "{}        \"password\": \"{}\"\n"
                           "{}      }}\n"
                           "{}    ]\n"
                           "{}  }}", indent, indent, indent, indent, p.server, indent, p.port, indent, p.uuid, indent, indent, indent);
    } else if (proto == "shadowsocks" || proto == "ss") {
        out += std::format("{}  \"settings\": {{\n"
                           "{}    \"servers\": [\n"
                           "{}      {{\n"
                           "{}        \"address\": \"{}\",\n"
                           "{}        \"port\": {},\n"
                           "{}        \"method\": \"{}\",\n"
                           "{}        \"password\": \"{}\"\n"
                           "{}      }}\n"
                           "{}    ]\n"
                           "{}  }}", indent, indent, indent, indent, p.server, indent, p.port, indent, p.cipher[0] ? p.cipher : "aes-128-gcm", indent, p.uuid, indent, indent, indent);
    } else if (proto == "socks" || proto == "http" || proto == "https") {
        out += std::format("{0}  \"settings\": {{\n"
                           "{0}    \"servers\": [\n"
                           "{0}      {{\n"
                           "{0}        \"address\": \"{1}\",\n"
                           "{0}        \"port\": {2},\n"
                           "{0}        \"users\": []\n"
                           "{0}      }}\n"
                           "{0}    ]\n"
                           "{0}  }}", indent, p.server, p.port);
    }

    std::string net = p.type[0] ? p.type : "tcp";
    if (net == "httpupgrade") net = "ws";

    out += std::format(",\n{}  \"streamSettings\": {{\n"
                       "{}    \"network\": \"{}\"", indent, indent, net);

    if (net == "tcp") {
        out += std::format(",\n{}    \"tcpSettings\": {{}}", indent);
    } else if (net == "ws") {
        out += std::format(",\n{}    \"wsSettings\": {{\n"
                           "{}      \"path\": \"{}\"", indent, indent, p.path[0] ? p.path : "/");
        if (p.host[0] || p.sni[0]) {
            out += std::format(",\n{}      \"headers\": {{ \"Host\": \"{}\" }}", indent, p.host[0] ? p.host : p.sni);
        }
        out += std::format("\n{}    }}", indent);
    } else if (net == "grpc") {
        out += std::format(",\n{}    \"grpcSettings\": {{\n"
                           "{}      \"serviceName\": \"{}\",\n"
                           "{}      \"multiMode\": false\n"
                           "{}    }}", indent, indent, p.path, indent, indent);
    } else if (net == "xhttp") {
        out += std::format(",\n{}    \"xhttpSettings\": {{\n"
                           "{}      \"path\": \"{}\"", indent, indent, p.path[0] ? p.path : "/");
        if (p.host[0] || p.sni[0]) {
            out += std::format(",\n{}      \"host\": \"{}\"", indent, p.host[0] ? p.host : p.sni);
        }
        if (p.mode[0]) {
            out += std::format(",\n{}      \"mode\": \"{}\"", indent, p.mode);
        }
        if (p.extra[0]) {
            out += std::format(",\n{}      \"extra\": {}", indent, p.extra);
        }
        out += std::format("\n{}    }}", indent);
    }

    std::string sec = p.security[0] ? p.security : "none";
    if (std::string_view(p.protocol) == "https" && sec == "none") sec = "tls";

    out += std::format(",\n{}    \"security\": \"{}\"", indent, sec);
    if (sec == "reality") {
        out += std::format(",\n{}    \"realitySettings\": {{\n"
                           "{}      \"serverName\": \"{}\",\n"
                           "{}      \"publicKey\": \"{}\"",
                           indent, indent, p.sni[0] ? p.sni : p.server, indent, p.pbk);
        if (p.sid[0]) out += std::format(",\n{}      \"shortId\": \"{}\"", indent, p.sid);
        if (p.fp[0]) out += std::format(",\n{}      \"fingerprint\": \"{}\"", indent, p.fp);
        out += std::format("\n{}    }}", indent);
    } else if (sec == "tls") {
        out += std::format(",\n{}    \"tlsSettings\": {{\n"
                           "{}      \"serverName\": \"{}\"", indent, indent, p.sni[0] ? p.sni : p.server);
        if (p.fp[0]) out += std::format(",\n{}      \"fingerprint\": \"{}\"", indent, p.fp);
        if (p.alpn[0]) {
            out += std::format(",\n{}      \"alpn\": [", indent);
            std::string_view alpn_str = p.alpn;
            size_t c = 0;
            bool first_a = true;
            while (c < alpn_str.length()) {
                size_t comma = alpn_str.find(',', c);
                if (comma == std::string_view::npos) comma = alpn_str.length();
                if (!first_a) out += ", ";
                out += std::format("\"{}\"", alpn_str.substr(c, comma - c));
                first_a = false;
                c = comma + 1;
            }
            out += "]";
        }
        out += std::format("\n{}    }}", indent);
    }

    out += std::format("\n{}  }}\n{}}}", indent, indent);
    return out;
}

std::string gen_xray(const std::vector<Proxy>& proxies, std::string_view remarks, const std::vector<Rule>& rules) {
    std::string out = "{\n"
                      "  \"dns\": {\n"
                      "    \"servers\": [\n"
                      "      \"https://8.8.8.8/dns-query\",\n"
                      "      \"https://1.1.1.1/dns-query\"\n"
                      "    ],\n"
                      "    \"queryStrategy\": \"UseIPv4\"\n"
                      "  },\n"
                      "  \"routing\": {\n"
                      "    \"rules\": [\n";

    bool first_rule = true;
    for (const auto& r : rules) {
        if (!first_rule) out += ",\n";
        first_rule = false;
        out += "      {\n"
               "        \"type\": \"field\",\n";
        
        std::string_view r_out = r.outbound;
        std::string tag;
        if (r_out == "block" || r_out == "reject") tag = "block";
        else if (r_out == "direct") tag = "direct";
        else tag = "proxy";
        out += std::format("        \"outboundTag\": \"{}\"", tag);

        if (!r.protocols.empty()) {
            out += ",\n        \"protocol\": [";
            for (size_t k = 0; k < r.protocols.size(); k++) {
                if (k > 0) out += ", ";
                out += std::format("\"{}\"", sanitize_json(r.protocols[k]));
            }
            out += "]";
        }
        if (!r.domains.empty()) {
            out += ",\n        \"domain\": [\n";
            for (size_t k = 0; k < r.domains.size(); k++) {
                if (k > 0) out += ",\n";
                std::string_view d = r.domains[k];
                if (d.starts_with("domain:")) d = d.substr(7);
                if (d.starts_with("full:")) d = d.substr(5);
                out += std::format("          \"{}\"", sanitize_json(d));
            }
            out += "\n        ]";
        }
        if (!r.ips.empty()) {
            out += ",\n        \"ip\": [\n";
            for (size_t k = 0; k < r.ips.size(); k++) {
                if (k > 0) out += ",\n";
                out += std::format("          \"{}\"", sanitize_json(r.ips[k]));
            }
            out += "\n        ]";
        }
        if (!r.port.empty()) {
            out += std::format(",\n        \"port\": \"{}\"", sanitize_json(r.port));
        }
        out += "\n      }";
    }

    out += "\n    ],\n"
           "    \"domainMatcher\": \"hybrid\",\n"
           "    \"domainStrategy\": \"IPIfNonMatch\"\n"
           "  },\n"
           "  \"inbounds\": [\n"
           "    {\n"
           "      \"tag\": \"socks\",\n"
           "      \"port\": 10808,\n"
           "      \"listen\": \"127.0.0.1\",\n"
           "      \"protocol\": \"socks\",\n"
           "      \"settings\": {\n"
           "        \"udp\": true,\n"
           "        \"auth\": \"noauth\"\n"
           "      },\n"
           "      \"sniffing\": {\n"
           "        \"enabled\": true,\n"
           "        \"routeOnly\": false,\n"
           "        \"destOverride\": [\"http\", \"tls\", \"quic\"]\n"
           "      }\n"
           "    },\n"
           "    {\n"
           "      \"tag\": \"http\",\n"
           "      \"port\": 10809,\n"
           "      \"listen\": \"127.0.0.1\",\n"
           "      \"protocol\": \"http\",\n"
           "      \"settings\": {\n"
           "        \"allowTransparent\": false\n"
           "      },\n"
           "      \"sniffing\": {\n"
           "        \"enabled\": true,\n"
           "        \"routeOnly\": false,\n"
           "        \"destOverride\": [\"http\", \"tls\", \"quic\"]\n"
           "      }\n"
           "    }\n"
           "  ],\n"
           "  \"outbounds\": [\n";

    bool first_out = true;
    for (size_t i = 0; i < proxies.size(); i++) {
        const auto& p = proxies[i];
        if (!p.protocol[0]) continue;

        if (!first_out) out += ",\n";
        first_out = false;

        std::string tag = (i == 0 && proxies.size() == 1) ? "proxy" : (p.name[0] ? sanitize_json(p.name) : std::format("proxy_{}", i + 1));
        out += format_xray_proxy_outbound(p, tag, "    ");
    }

    if (!first_out) out += ",\n";
    out += "    {\n      \"tag\": \"direct\",\n      \"protocol\": \"freedom\"\n    },\n"
           "    {\n      \"tag\": \"block\",\n      \"protocol\": \"blackhole\"\n    }\n"
           "  ]";

    if (!remarks.empty()) {
        out += std::format(",\n  \"remarks\": \"{}\"", sanitize_json(remarks));
    }

    out += "\n}\n";
    return out;
}

std::string gen_v2ray(const std::vector<Proxy>& proxies) {
    std::string out;
    for (const auto& p : proxies) {
        if (!p.protocol[0]) continue;
        std::string_view proto = p.protocol;
        if (proto == "vless" || proto == "trojan") {
            std::string uri = std::format("{}://{}@{}:{}?", p.protocol, p.uuid, p.server, p.port);
            if (proto == "vless") uri += "encryption=none&";
            
            std::string net = p.type[0] ? p.type : "tcp";
            if (net == "httpupgrade") net = "ws";
            uri += std::format("type={}&", net);

            if (p.security[0]) uri += std::format("security={}&", p.security);
            if (p.flow[0]) uri += std::format("flow={}&", p.flow);
            if (p.sni[0]) uri += std::format("sni={}&", p.sni);
            if (p.fp[0]) uri += std::format("fp={}&", p.fp);
            if (p.pbk[0]) uri += std::format("pbk={}&", p.pbk);
            if (p.sid[0]) uri += std::format("sid={}&", p.sid);
            if (p.host[0]) uri += std::format("host={}&", url_encode(p.host));

            if (net == "grpc") {
                uri += std::format("serviceName={}&", url_encode(p.path));
                uri += std::format("mode={}&", p.mode[0] ? p.mode : "gun");
            } else if (p.path[0]) {
                uri += std::format("path={}&", url_encode(p.path));
            }

            if (p.alpn[0]) uri += std::format("alpn={}&", url_encode(p.alpn));
            if (p.extra[0]) uri += std::format("extra={}&", url_encode(p.extra));
            
            if (uri.back() == '&' || uri.back() == '?') uri.pop_back();
            
            uri += std::format("#{}\n", url_encode(p.name));
            out += uri;
        }
        else if (proto == "shadowsocks" || proto == "ss") {
            std::string userinfo = std::format("{}:{}", p.cipher[0] ? p.cipher : "aes-128-gcm", p.uuid);
            std::string uri = std::format("ss://{}@{}:{}#{}\n",
                                          base64_encode(userinfo), p.server, p.port, url_encode(p.name));
            out += uri;
        }
        else if (proto == "vmess") {
            std::string json = std::format("{{\"v\":\"2\",\"ps\":\"{}\",\"add\":\"{}\",\"port\":\"{}\",\"id\":\"{}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"{}\",\"type\":\"none\",\"host\":\"{}\",\"path\":\"{}\",\"tls\":\"{}\",\"sni\":\"{}\",\"alpn\":\"{}\"}}",
                                           p.name, p.server, p.port, p.uuid, p.type[0] ? p.type : "tcp",
                                           p.host, p.path, p.security[0] ? p.security : "", p.sni, p.alpn);
            out += std::format("vmess://{}\n", base64_encode(json));
        }
        else if (proto == "hysteria2" || proto == "hy2") {
            std::string uri = std::format("hysteria2://{}@{}:{}?", p.uuid, p.server, p.port);
            if (p.sni[0]) uri += std::format("sni={}&", p.sni);
            if (p.obfs[0]) uri += std::format("obfs={}&", p.obfs);
            if (p.obfs_pass[0]) uri += std::format("obfs-password={}&", p.obfs_pass);
            if (uri.back() == '&' || uri.back() == '?') uri.pop_back();
            uri += std::format("#{}\n", url_encode(p.name));
            out += uri;
        }
        else if (proto == "hysteria") {
            std::string uri = std::format("hysteria://{}@{}:{}?", p.uuid, p.server, p.port);
            if (p.sni[0]) uri += std::format("peer={}&", p.sni);
            if (p.obfs[0]) uri += std::format("obfs={}&", p.obfs);
            if (p.obfs_pass[0]) uri += std::format("obfsParam={}&", p.obfs_pass);
            if (p.up[0]) uri += std::format("upmbps={}&", p.up);
            if (p.down[0]) uri += std::format("downmbps={}&", p.down);
            if (p.alpn[0]) uri += std::format("alpn={}&", p.alpn);
            if (uri.back() == '&' || uri.back() == '?') uri.pop_back();
            uri += std::format("#{}\n", url_encode(p.name));
            out += uri;
        }
    }
    return base64_encode(out);
}

std::string gen_xray_jsons(const std::vector<Proxy>& proxies,
                           const std::vector<Balancer>& balancers,
                           const std::vector<Rule>& rules) {
    std::string out = "[\n";
    bool first_config = true;

    for (const auto& b : balancers) {
        if (!first_config) out += ",\n";
        first_config = false;

        std::string b_tag = b.name[0] ? sanitize_json(b.name) : "Super_Balancer";

        out += "  {\n"
               "    \"dns\": {\n"
               "      \"servers\": [\n"
               "        \"1.1.1.1\",\n"
               "        \"1.0.0.1\"\n"
               "      ],\n"
               "      \"queryStrategy\": \"UseIP\"\n"
               "    },\n"
               "    \"routing\": {\n"
               "      \"rules\": [\n";

        bool first_r = true;
        for (const auto& r : rules) {
            if (!first_r) out += ",\n";
            first_r = false;
            out += "        {\n"
                   "          \"type\": \"field\",\n";
            std::string_view r_out = r.outbound;
            std::string tag;
            if (r_out == "block" || r_out == "reject") tag = "block";
            else if (r_out == "direct") tag = "direct";
            else tag = "proxy";
            out += std::format("          \"outboundTag\": \"{}\"", tag);

            if (!r.protocols.empty()) {
                out += ",\n          \"protocol\": [";
                for (size_t k = 0; k < r.protocols.size(); k++) {
                    if (k > 0) out += ", ";
                    out += std::format("\"{}\"", sanitize_json(r.protocols[k]));
                }
                out += "]";
            }
            if (!r.domains.empty()) {
                out += ",\n          \"domain\": [\n";
                for (size_t k = 0; k < r.domains.size(); k++) {
                    if (k > 0) out += ",\n";
                    std::string_view d = r.domains[k];
                    if (d.starts_with("domain:")) d = d.substr(7);
                    if (d.starts_with("full:")) d = d.substr(5);
                    out += std::format("            \"{}\"", sanitize_json(d));
                }
                out += "\n          ]";
            }
            if (!r.ips.empty()) {
                out += ",\n          \"ip\": [\n";
                for (size_t k = 0; k < r.ips.size(); k++) {
                    if (k > 0) out += ",\n";
                    out += std::format("            \"{}\"", sanitize_json(r.ips[k]));
                }
                out += "\n          ]";
            }
            if (!r.port.empty()) {
                out += std::format(",\n          \"port\": \"{}\"", sanitize_json(r.port));
            }
            out += "\n        }";
        }

        if (!first_r) out += ",\n";
        out += std::format("        {{\n"
                           "          \"type\": \"field\",\n"
                           "          \"network\": \"tcp,udp\",\n"
                           "          \"balancerTag\": \"{}\"\n"
                           "        }}\n"
                           "      ],\n"
                           "      \"balancers\": [\n"
                           "        {{\n"
                           "          \"tag\": \"{}\",\n"
                           "          \"selector\": [\n"
                           "            \"proxy\"\n"
                           "          ],\n"
                           "          \"strategy\": {{\n"
                           "            \"type\": \"leastPing\"\n"
                           "          }},\n"
                           "          \"fallbackTag\": \"direct\"\n"
                           "        }}\n"
                           "      ],\n", b_tag, b_tag);

        out += "      \"domainMatcher\": \"hybrid\",\n"
               "      \"domainStrategy\": \"IPIfNonMatch\"\n"
               "    },\n"
               "    \"inbounds\": [\n"
               "      {\n"
               "        \"tag\": \"socks\",\n"
               "        \"port\": 10808,\n"
               "        \"listen\": \"127.0.0.1\",\n"
               "        \"protocol\": \"socks\",\n"
               "        \"settings\": {\n"
               "          \"udp\": true,\n"
               "          \"auth\": \"noauth\"\n"
               "        },\n"
               "        \"sniffing\": {\n"
               "          \"enabled\": true,\n"
               "          \"routeOnly\": false,\n"
               "          \"destOverride\": [\"http\", \"tls\", \"quic\"]\n"
               "        }\n"
               "      },\n"
               "      {\n"
               "        \"tag\": \"http\",\n"
               "        \"port\": 10809,\n"
               "        \"listen\": \"127.0.0.1\",\n"
               "        \"protocol\": \"http\",\n"
               "        \"settings\": {\n"
               "          \"allowTransparent\": false\n"
               "        },\n"
               "        \"sniffing\": {\n"
               "          \"enabled\": true,\n"
               "          \"routeOnly\": false,\n"
               "          \"destOverride\": [\"http\", \"tls\", \"quic\"]\n"
               "        }\n"
               "      }\n"
               "    ],\n"
               "    \"outbounds\": [\n";

        std::vector<const Proxy*> member_proxies;
        for (const auto& pname : b.proxies) {
            for (const auto& p : proxies) {
                if (pname == p.name) {
                    member_proxies.push_back(&p);
                    break;
                }
            }
        }
        if (member_proxies.empty()) {
            for (const auto& p : proxies) {
                member_proxies.push_back(&p);
            }
        }

        for (size_t m = 0; m < member_proxies.size(); m++) {
            std::string tag = (m == 0) ? "proxy" : std::format("proxy-{}", m + 1);
            out += format_xray_proxy_outbound(*member_proxies[m], tag, "      ");
            out += ",\n";
        }

        out += "      {\n"
               "        \"tag\": \"direct\",\n"
               "        \"protocol\": \"freedom\"\n"
               "      },\n"
               "      {\n"
               "        \"tag\": \"block\",\n"
               "        \"protocol\": \"blackhole\"\n"
               "      }\n"
               "    ],\n"
               "    \"burstObservatory\": {\n"
               "      \"pingConfig\": {\n"
               "        \"timeout\": \"3s\",\n"
               "        \"interval\": \"1m\",\n"
               "        \"sampling\": 1,\n"
               "        \"destination\": \"https://cp.cloudflare.com/generate_204\",\n"
               "        \"connectivity\": \"\"\n"
               "      },\n"
               "      \"subjectSelector\": [\n"
               "        \"proxy\"\n"
               "      ]\n"
               "    },\n";

        out += std::format("    \"remarks\": \"{}\"\n"
                           "  }}", sanitize_json(b.name));
    }

    for (const auto& p : proxies) {
        if (!p.protocol[0]) continue;
        if (!first_config) out += ",\n";
        first_config = false;

        std::string single_cfg = gen_xray({p}, p.name, rules);
        std::string indented;
        indented.reserve(single_cfg.size() + 100);
        size_t start = 0;
        while (start < single_cfg.size()) {
            size_t end = single_cfg.find('\n', start);
            if (end == std::string::npos) end = single_cfg.size();
            std::string_view line = std::string_view(single_cfg).substr(start, end - start);
            if (!line.empty() || end < single_cfg.size()) {
                indented += "  ";
                indented += line;
                if (end < single_cfg.size()) indented += '\n';
            }
            start = end + 1;
        }
        while (!indented.empty() && (indented.back() == '\n' || indented.back() == '\r')) {
            indented.pop_back();
        }
        out += indented;
    }

    out += "\n]\n";
    return out;
}
