#include "generator.h"
#include "utils.h"
#include <cstring>

std::string gen_clash(const std::vector<Proxy>& proxies, const std::vector<Rule>& rules) {
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
        proxy_names += "      - " + s_name + "\n";
        
        out += "  - name: " + s_name + "\n";
        out += "    type: " + std::string(p.protocol) + "\n";
        out += "    server: " + std::string(p.server) + "\n";
        out += "    port: " + std::to_string(p.port) + "\n";

        if (strcmp(p.protocol, "vless") == 0 || strcmp(p.protocol, "vmess") == 0) {
            out += "    uuid: " + std::string(p.uuid) + "\n";
            if (strcmp(p.protocol, "vmess") == 0) {
                out += "    alterId: 0\n";
                out += "    cipher: auto\n";
            }
            if (strcmp(p.protocol, "vless") == 0) {
                out += "    udp: true\n";
                out += "    packet-encoding: xudp\n";
                if (p.flow[0]) {
                    out += "    flow: " + std::string(p.flow) + "\n";
                }
            }
        } else if (strcmp(p.protocol, "trojan") == 0) {
            out += "    password: " + std::string(p.uuid) + "\n";
            out += "    udp: true\n";
        } else if (strcmp(p.protocol, "hysteria2") == 0) {
            out += "    password: " + std::string(p.uuid) + "\n";
            if (p.sni[0]) out += "    sni: " + std::string(p.sni) + "\n";
            if (p.obfs[0]) out += "    obfs: " + std::string(p.obfs) + "\n";
            if (p.obfs_pass[0]) out += "    obfs-password: " + std::string(p.obfs_pass) + "\n";
            out += "    up: " + std::string(p.up[0] ? p.up : "100 Mbps") + "\n";
            out += "    down: " + std::string(p.down[0] ? p.down : "100 Mbps") + "\n";
            out += "    skip-cert-verify: false\n";
        } else if (strcmp(p.protocol, "hysteria") == 0) {
            out += "    auth_str: " + std::string(p.uuid) + "\n";
            if (p.sni[0]) out += "    sni: " + std::string(p.sni) + "\n";
            if (p.obfs[0]) out += "    obfs: " + std::string(p.obfs) + "\n";
            if (p.obfs_pass[0]) out += "    obfs-parameter: " + std::string(p.obfs_pass) + "\n";
            out += "    up: " + std::string(p.up[0] ? p.up : "100 Mbps") + "\n";
            out += "    down: " + std::string(p.down[0] ? p.down : "100 Mbps") + "\n";
            out += "    skip-cert-verify: false\n";
        }

        std::string net = p.type;
        if (strcmp(p.type, "httpupgrade") == 0) net = "ws";
        if (strcmp(p.protocol, "hysteria2") != 0 && strcmp(p.protocol, "hysteria") != 0 && p.type[0]) out += "    network: " + net + "\n";

        if (strcmp(p.security, "tls") == 0 || strcmp(p.security, "reality") == 0) {
            out += "    tls: true\n";
            if (p.sni[0]) out += "    servername: " + std::string(p.sni) + "\n";
            if (p.fp[0]) out += "    client-fingerprint: " + std::string(p.fp) + "\n";
            if (p.alpn[0]) {
                out += "    alpn:\n";
                std::string alpn_str = p.alpn;
                size_t s = 0;
                while (s < alpn_str.length()) {
                    size_t c = alpn_str.find(',', s);
                    if (c == std::string::npos) c = alpn_str.length();
                    out += "      - " + alpn_str.substr(s, c - s) + "\n";
                    s = c + 1;
                }
            }
        }

        if (strcmp(p.security, "reality") == 0) {
            out += "    reality-opts:\n";
            out += "      public-key: " + std::string(p.pbk) + "\n";
            if (p.sid[0]) out += "      short-id: " + std::string(p.sid) + "\n";
        }

        if (strcmp(p.type, "ws") == 0) {
            out += "    ws-opts:\n";
            out += "      path: \"" + std::string(p.path[0] ? p.path : "/") + "\"\n";
            out += "      headers:\n";
            out += "        Host: " + std::string(p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server)) + "\n";
        } else if (strcmp(p.type, "grpc") == 0) {
            out += "    grpc-opts:\n";
            out += "      grpc-service-name: " + std::string(p.path) + "\n";
        } else if (strcmp(p.type, "xhttp") == 0) {
            out += "    xhttp-opts:\n";
            out += "      path: " + std::string(p.path[0] ? p.path : "/") + "\n";
            out += "      host: " + std::string(p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server)) + "\n";
            if (p.mode[0]) out += "      mode: " + std::string(p.mode) + "\n";
            if (p.extra[0]) out += "      extra: " + std::string(p.extra) + "\n";
        } else if (strcmp(p.type, "httpupgrade") == 0) {
            out += "    ws-opts:\n";
            out += "      path: " + std::string(p.path[0] ? p.path : "/") + "\n";
            out += "      headers:\n";
            out += "        Host: " + std::string(p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server)) + "\n";
            out += "      v2ray-http-upgrade: true\n";
            out += "      v2ray-http-upgrade-fast-open: true\n";
        }
    }
    
    out += "proxy-groups:\n"
           "  - name: Proxy\n"
           "    type: select\n"
           "    proxies:\n"
           "      - Auto\n"
           + proxy_names + 
           "  - name: Auto\n"
           "    type: url-test\n"
           "    url: http://www.gstatic.com/generate_204\n"
           "    interval: 300\n"
           "    proxies:\n"
           + proxy_names +
           "rules:\n";

    std::string clash_rules;
    for (const auto& r : rules) {
        std::string target = "Proxy";
        if (strcmp(r.outbound, "direct") == 0) target = "DIRECT";
        else if (strcmp(r.outbound, "block") == 0 || strcmp(r.outbound, "reject") == 0) target = "REJECT";
        else if (strcmp(r.outbound, "proxy") == 0 || strcmp(r.outbound, "Proxy") == 0) target = "Proxy";
        else if (r.outbound[0] != '\0') target = r.outbound;

        for (const auto& dom : r.domains) {
            std::string d = dom;
            if (d.rfind("domain:", 0) == 0) d = d.substr(7);
            if (d.rfind("full:", 0) == 0) {
                clash_rules += "  - DOMAIN," + d.substr(5) + "," + target + "\n";
            } else if (d.rfind("geosite:", 0) == 0) {
                clash_rules += "  - GEOSITE," + d.substr(8) + "," + target + "\n";
            } else if (d.rfind("regexp:", 0) != 0) {
                clash_rules += "  - DOMAIN-SUFFIX," + d + "," + target + "\n";
            }
        }
        for (const auto& ip : r.ips) {
            std::string i = ip;
            if (i == "geoip:private") {
                clash_rules += "  - GEOIP,private," + target + ",no-resolve\n";
            } else if (i.rfind("geoip:", 0) == 0) {
                clash_rules += "  - GEOIP," + i.substr(6) + "," + target + ",no-resolve\n";
            } else {
                bool is_v6 = (i.find(':') != std::string::npos);
                if (i.find('/') == std::string::npos) {
                    if (is_v6) clash_rules += "  - IP-CIDR6," + i + "/128," + target + ",no-resolve\n";
                    else clash_rules += "  - IP-CIDR," + i + "/32," + target + ",no-resolve\n";
                } else {
                    if (is_v6) clash_rules += "  - IP-CIDR6," + i + "," + target + ",no-resolve\n";
                    else clash_rules += "  - IP-CIDR," + i + "," + target + ",no-resolve\n";
                }
            }
        }
        if (!r.port.empty()) {
            clash_rules += "  - DST-PORT," + r.port + "," + target + "\n";
        }
    }
    clash_rules += "  - MATCH,Proxy\n";
    out += clash_rules;
    return out;
}

std::string gen_singbox(const std::vector<Proxy>& proxies, const std::string& platform, const std::vector<Rule>& rules) {
    std::string route_extra = (platform == "pc") ? "" : ",\"override_android_vpn\":true,\"auto_detect_interface\":true";
    std::string sing_rules = "[{\"action\":\"sniff\"},{\"mode\":\"or\",\"type\":\"logical\",\"rules\":[{\"protocol\":\"dns\"},{\"port\":53}],\"action\":\"hijack-dns\"},{\"outbound\":\"direct\",\"ip_is_private\":true}";

    for (const auto& r : rules) {
        std::string target_out = "Proxy";
        bool is_reject = (strcmp(r.outbound, "block") == 0 || strcmp(r.outbound, "reject") == 0);
        if (strcmp(r.outbound, "direct") == 0) target_out = "direct";
        else if (strcmp(r.outbound, "proxy") == 0 || strcmp(r.outbound, "Proxy") == 0) target_out = "Proxy";
        else if (r.outbound[0] != '\0') target_out = r.outbound;

        if (!r.protocols.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += "\"outbound\":\"" + target_out + "\",";
            sing_rules += "\"protocol\":[";
            for (size_t k = 0; k < r.protocols.size(); k++) {
                if (k > 0) sing_rules += ",";
                sing_rules += "\"" + sanitize_json(r.protocols[k]) + "\"";
            }
            sing_rules += "]}";
        }

        if (!r.domains.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += "\"outbound\":\"" + target_out + "\",";
            sing_rules += "\"domain_suffix\":[";
            for (size_t k = 0; k < r.domains.size(); k++) {
                if (k > 0) sing_rules += ",";
                std::string d = r.domains[k];
                if (d.rfind("domain:", 0) == 0) d = d.substr(7);
                if (d.rfind("full:", 0) == 0) d = d.substr(5);
                sing_rules += "\"" + sanitize_json(d) + "\"";
            }
            sing_rules += "]}";
        }

        if (!r.ips.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += "\"outbound\":\"" + target_out + "\",";
            sing_rules += "\"ip_cidr\":[";
            for (size_t k = 0; k < r.ips.size(); k++) {
                if (k > 0) sing_rules += ",";
                std::string i = r.ips[k];
                if (i.find('/') == std::string::npos) {
                    if (i.find(':') != std::string::npos) i += "/128";
                    else i += "/32";
                }
                sing_rules += "\"" + sanitize_json(i) + "\"";
            }
            sing_rules += "]}";
        }

        if (!r.port.empty()) {
            sing_rules += ",{";
            if (is_reject) sing_rules += "\"action\":\"reject\",";
            else sing_rules += "\"outbound\":\"" + target_out + "\",";
            sing_rules += "\"port\":[" + r.port + "]}";
        }
    }
    sing_rules += "]";

    std::string out = "{\n"
                      "  \"dns\": {\"strategy\":\"ipv4_only\",\"rules\":[{\"server\":\"remote\",\"query_type\":[\"A\",\"AAAA\"]}],\"servers\":[{\"tag\":\"cf-dns\",\"type\":\"tls\",\"server\":\"1.1.1.1\"},{\"tag\":\"local\",\"type\":\"tcp\",\"server\":\"1.1.1.1\"},{\"tag\":\"remote\",\"type\":\"fakeip\",\"inet4_range\":\"198.18.0.0/15\",\"inet6_range\":\"fc00::/18\"}]},\n"
                      "  \"log\": {\"level\":\"info\",\"disabled\":false,\"timestamp\":true},\n"
                      "  \"route\": {\"default_domain_resolver\":\"local\",\"rules\":" + sing_rules + route_extra + "},\n"
                      "  \"inbounds\": [{\"mtu\":9000,\"tag\":\"tun-in\",\"type\":\"tun\",\"stack\":\"mixed\",\"auto_route\":true,\"strict_route\":true,\"address\":[\"172.19.0.1/30\",\"fdfe:dcba:9876::1/126\"],\"endpoint_independent_nat\":true},{\"tag\":\"mixed-in\",\"type\":\"mixed\",\"users\":[],\"listen\":\"127.0.0.1\",\"listen_port\":2412,\"set_system_proxy\":false}],\n"
                      "  \"outbounds\": [\n";
    std::string proxy_tags = "";
    std::string outbounds_arr = "";
    bool first = true;
    for (size_t i = 0; i < proxies.size(); i++) {
        const auto& p = proxies[i];
        if (!p.protocol[0]) continue;
        if (strcmp(p.type, "xhttp") == 0) continue; // Sing-box does not support xhttp
        
        if (!first) outbounds_arr += ",\n";
        first = false;
        
        std::string s_name = sanitize_json(p.name);
        proxy_tags += "\"" + s_name + "\",";
        
        std::string sb_type = p.protocol;
        if (sb_type == "https") sb_type = "http";
        else if (sb_type == "ss") sb_type = "shadowsocks";
        else if (sb_type == "socks5") sb_type = "socks";
        else if (sb_type == "hy2") sb_type = "hysteria2";

        outbounds_arr += "    {\n";
        outbounds_arr += "      \"type\": \"" + sb_type + "\",\n";
        outbounds_arr += "      \"tag\": \"" + s_name + "\",\n";
        outbounds_arr += "      \"server\": \"" + std::string(p.server) + "\",\n";
        outbounds_arr += "      \"server_port\": " + std::to_string(p.port);

        if (strcmp(p.protocol, "vless") == 0 || strcmp(p.protocol, "vmess") == 0) {
            outbounds_arr += ",\n      \"uuid\": \"" + std::string(p.uuid) + "\"";
            if (strcmp(p.protocol, "vmess") == 0) {
                outbounds_arr += ",\n      \"security\": \"auto\"";
            }
            if (strcmp(p.protocol, "vless") == 0 && p.flow[0]) {
                outbounds_arr += ",\n      \"flow\": \"" + std::string(p.flow) + "\"";
            }
        } else if (strcmp(p.protocol, "trojan") == 0) {
            outbounds_arr += ",\n      \"password\": \"" + std::string(p.uuid) + "\"";
        } else if (strcmp(p.protocol, "shadowsocks") == 0 || strcmp(p.protocol, "ss") == 0) {
            outbounds_arr += ",\n      \"method\": \"" + std::string(p.cipher[0] ? p.cipher : "aes-128-gcm") + "\"";
            outbounds_arr += ",\n      \"password\": \"" + std::string(p.uuid) + "\"";
        } else if (strcmp(p.protocol, "http") == 0 || strcmp(p.protocol, "https") == 0) {
            if (p.uuid[0]) {
                outbounds_arr += ",\n      \"password\": \"" + std::string(p.uuid) + "\"";
            }
            if (strcmp(p.protocol, "https") == 0 || strcmp(p.security, "tls") == 0) {
                outbounds_arr += ",\n      \"tls\": {\n        \"enabled\": true";
                if (p.sni[0]) outbounds_arr += ",\n        \"server_name\": \"" + std::string(p.sni) + "\"";
                outbounds_arr += "\n      }";
            }
        } else if (strcmp(p.protocol, "socks") == 0 || strcmp(p.protocol, "socks5") == 0) {
            outbounds_arr += ",\n      \"version\": \"5\"";
            if (p.uuid[0]) {
                outbounds_arr += ",\n      \"password\": \"" + std::string(p.uuid) + "\"";
            }
        } else if (strcmp(p.protocol, "hysteria2") == 0 || strcmp(p.protocol, "hy2") == 0) {
            outbounds_arr += ",\n      \"password\": \"" + std::string(p.uuid) + "\"";
            outbounds_arr += ",\n      \"tls\": {\n";
            outbounds_arr += "        \"enabled\": true";
            if (p.sni[0]) outbounds_arr += ",\n        \"server_name\": \"" + std::string(p.sni) + "\"";
            outbounds_arr += "\n      }";
            if (p.obfs[0]) {
                outbounds_arr += ",\n      \"obfs\": {\n";
                outbounds_arr += "        \"type\": \"" + std::string(p.obfs) + "\"";
                if (p.obfs_pass[0]) outbounds_arr += ",\n        \"password\": \"" + std::string(p.obfs_pass) + "\"";
                outbounds_arr += "\n      }";
            }
        } else if (strcmp(p.protocol, "hysteria") == 0) {
            outbounds_arr += ",\n      \"auth_str\": \"" + std::string(p.uuid) + "\"";
            outbounds_arr += ",\n      \"tls\": {\n";
            outbounds_arr += "        \"enabled\": true";
            if (p.sni[0]) outbounds_arr += ",\n        \"server_name\": \"" + std::string(p.sni) + "\"";
            outbounds_arr += "\n      }";
            if (p.obfs[0]) {
                outbounds_arr += ",\n      \"obfs\": {\n";
                outbounds_arr += "        \"type\": \"" + std::string(p.obfs) + "\"";
                if (p.obfs_pass[0]) outbounds_arr += ",\n        \"password\": \"" + std::string(p.obfs_pass) + "\"";
                outbounds_arr += "\n      }";
            }
            if (p.up[0]) {
                int up_val = atoi(p.up);
                if (up_val > 0) outbounds_arr += ",\n      \"up_mbps\": " + std::to_string(up_val);
            }
            if (p.down[0]) {
                int down_val = atoi(p.down);
                if (down_val > 0) outbounds_arr += ",\n      \"down_mbps\": " + std::to_string(down_val);
            }
        }

        if (strcmp(p.protocol, "hysteria2") != 0 && strcmp(p.protocol, "hy2") != 0 && strcmp(p.protocol, "hysteria") != 0 && strcmp(p.protocol, "http") != 0 && strcmp(p.protocol, "https") != 0 && (strcmp(p.security, "tls") == 0 || strcmp(p.security, "reality") == 0)) {
            outbounds_arr += ",\n      \"tls\": {\n";
            outbounds_arr += "        \"enabled\": true";
            if (p.sni[0]) outbounds_arr += ",\n        \"server_name\": \"" + std::string(p.sni) + "\"";
            if (p.fp[0]) outbounds_arr += ",\n        \"utls\": { \"enabled\": true, \"fingerprint\": \"" + std::string(p.fp) + "\" }";
            if (p.alpn[0]) {
                outbounds_arr += ",\n        \"alpn\": [";
                std::string alpn_str = p.alpn;
                size_t s = 0;
                bool first_alpn = true;
                while (s < alpn_str.length()) {
                    size_t c = alpn_str.find(',', s);
                    if (c == std::string::npos) c = alpn_str.length();
                    if (!first_alpn) outbounds_arr += ", ";
                    outbounds_arr += "\"" + alpn_str.substr(s, c - s) + "\"";
                    first_alpn = false;
                    s = c + 1;
                }
                outbounds_arr += "]";
            }
            if (strcmp(p.security, "reality") == 0) {
                outbounds_arr += ",\n        \"reality\": {\n";
                outbounds_arr += "          \"enabled\": true,\n";
                outbounds_arr += "          \"public_key\": \"" + std::string(p.pbk) + "\"";
                if (p.sid[0]) outbounds_arr += ",\n          \"short_id\": \"" + std::string(p.sid) + "\"";
                outbounds_arr += "\n        }";
            }
            outbounds_arr += "\n      }";
        }

        if (strcmp(p.protocol, "hysteria2") != 0 && strcmp(p.protocol, "hy2") != 0 && strcmp(p.protocol, "hysteria") != 0 && p.type[0] && strcmp(p.type, "tcp") != 0) {
            outbounds_arr += ",\n      \"transport\": {\n";
            outbounds_arr += "        \"type\": \"" + std::string(p.type) + "\"";
            if (strcmp(p.type, "ws") == 0 || strcmp(p.type, "httpupgrade") == 0 || strcmp(p.type, "xhttp") == 0) {
                outbounds_arr += ",\n        \"path\": \"" + std::string(p.path[0] ? p.path : "/") + "\"";
                outbounds_arr += ",\n        \"headers\": { \"Host\": \"" + std::string(p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server)) + "\" }";
                if (strcmp(p.type, "xhttp") == 0 && p.extra[0]) {
                    outbounds_arr += ",\n        \"extra\": " + std::string(p.extra);
                }
            } else if (strcmp(p.type, "grpc") == 0) {
                outbounds_arr += ",\n        \"service_name\": \"" + std::string(p.path) + "\"";
            }
            outbounds_arr += "\n      }";
        }

        outbounds_arr += "\n    }";
    }
    
    if (!proxy_tags.empty()) {
        proxy_tags.pop_back(); // ,
        out += "    {\n      \"type\": \"selector\",\n      \"tag\": \"Proxy\",\n      \"outbounds\": [\"Auto\", " + proxy_tags + "]\n    },\n";
        out += "    {\n      \"type\": \"urltest\",\n      \"tag\": \"Auto\",\n      \"outbounds\": [" + proxy_tags + "]\n    },\n";
    }

    out += "    {\n      \"tag\": \"direct\",\n      \"type\": \"direct\"\n    }";
    if (!outbounds_arr.empty()) {
        out += ",\n" + outbounds_arr;
    }
    out += "\n  ]\n}\n";
    return out;
}

std::string gen_xray(const std::vector<Proxy>& proxies, const std::string& remarks, const std::vector<Rule>& rules) {
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
        
        std::string tag = r.outbound;
        if (tag == "block" || tag == "reject") tag = "block";
        else if (tag == "direct") tag = "direct";
        else tag = "proxy";
        out += "        \"outboundTag\": \"" + tag + "\"";

        if (!r.protocols.empty()) {
            out += ",\n        \"protocol\": [";
            for (size_t k = 0; k < r.protocols.size(); k++) {
                if (k > 0) out += ", ";
                out += "\"" + sanitize_json(r.protocols[k]) + "\"";
            }
            out += "]";
        }
        if (!r.domains.empty()) {
            out += ",\n        \"domain\": [\n";
            for (size_t k = 0; k < r.domains.size(); k++) {
                if (k > 0) out += ",\n";
                std::string d = r.domains[k];
                if (d.rfind("domain:", 0) == 0) d = d.substr(7);
                if (d.rfind("full:", 0) == 0) d = d.substr(5);
                out += "          \"" + sanitize_json(d) + "\"";
            }
            out += "\n        ]";
        }
        if (!r.ips.empty()) {
            out += ",\n        \"ip\": [\n";
            for (size_t k = 0; k < r.ips.size(); k++) {
                if (k > 0) out += ",\n";
                out += "          \"" + sanitize_json(r.ips[k]) + "\"";
            }
            out += "\n        ]";
        }
        if (!r.port.empty()) {
            out += ",\n        \"port\": \"" + sanitize_json(r.port) + "\"";
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

        std::string tag = (i == 0 && proxies.size() == 1) ? "proxy" : (p.name[0] ? sanitize_json(p.name) : ("proxy_" + std::to_string(i + 1)));

        std::string proto = p.protocol;
        if (proto == "hy2" || proto == "hysteria2" || proto == "hysteria") proto = "vless";

        out += "    {\n";
        out += "      \"tag\": \"" + tag + "\",\n";
        out += "      \"protocol\": \"" + proto + "\",\n";

        if (proto == "vless" || proto == "vmess") {
            out += "      \"settings\": {\n"
                   "        \"vnext\": [\n"
                   "          {\n"
                   "            \"address\": \"" + std::string(p.server) + "\",\n"
                   "            \"port\": " + std::to_string(p.port) + ",\n"
                   "            \"users\": [\n"
                   "              {\n"
                   "                \"id\": \"" + std::string(p.uuid) + "\"";
            if (proto == "vless") {
                out += ",\n                \"encryption\": \"none\"";
                if (p.flow[0]) out += ",\n                \"flow\": \"" + std::string(p.flow) + "\"";
            } else if (proto == "vmess") {
                int alt = (p.alterId[0]) ? atoi(p.alterId) : 0;
                out += ",\n                \"alterId\": " + std::to_string(alt);
                out += ",\n                \"security\": \"" + std::string(p.cipher[0] ? p.cipher : "auto") + "\"";
            }
            out += "\n              }\n"
                   "            ]\n"
                   "          }\n"
                   "        ]\n"
                   "      }";
        } else if (proto == "trojan") {
            out += "      \"settings\": {\n"
                   "        \"servers\": [\n"
                   "          {\n"
                   "            \"address\": \"" + std::string(p.server) + "\",\n"
                   "            \"port\": " + std::to_string(p.port) + ",\n"
                   "            \"password\": \"" + std::string(p.uuid) + "\"\n"
                   "          }\n"
                   "        ]\n"
                   "      }";
        } else if (proto == "shadowsocks" || proto == "ss") {
            out += "      \"settings\": {\n"
                   "        \"servers\": [\n"
                   "          {\n"
                   "            \"address\": \"" + std::string(p.server) + "\",\n"
                   "            \"port\": " + std::to_string(p.port) + ",\n"
                   "            \"method\": \"" + std::string(p.cipher[0] ? p.cipher : "aes-128-gcm") + "\",\n"
                   "            \"password\": \"" + std::string(p.uuid) + "\"\n"
                   "          }\n"
                   "        ]\n"
                   "      }";
        } else if (proto == "socks" || proto == "http" || proto == "https") {
            out += "      \"settings\": {\n"
                   "        \"servers\": [\n"
                   "          {\n"
                   "            \"address\": \"" + std::string(p.server) + "\",\n"
                   "            \"port\": " + std::to_string(p.port) + ",\n"
                   "            \"users\": []\n"
                   "          }\n"
                   "        ]\n"
                   "      }";
        }

        std::string net = p.type[0] ? p.type : "tcp";
        if (net == "httpupgrade") net = "ws";

        out += ",\n      \"streamSettings\": {\n";
        out += "        \"network\": \"" + net + "\"";

        if (net == "tcp") {
            out += ",\n        \"tcpSettings\": {}";
        } else if (net == "ws") {
            out += ",\n        \"wsSettings\": {\n"
                   "          \"path\": \"" + std::string(p.path[0] ? p.path : "/") + "\"";
            if (p.host[0] || p.sni[0]) {
                out += ",\n          \"headers\": { \"Host\": \"" + std::string(p.host[0] ? p.host : p.sni) + "\" }";
            }
            out += "\n        }";
        } else if (net == "grpc") {
            out += ",\n        \"grpcSettings\": {\n"
                   "          \"serviceName\": \"" + std::string(p.path) + "\",\n"
                   "          \"multiMode\": false\n"
                   "        }";
        } else if (net == "xhttp") {
            out += ",\n        \"xhttpSettings\": {\n"
                   "          \"path\": \"" + std::string(p.path[0] ? p.path : "/") + "\"";
            if (p.host[0] || p.sni[0]) {
                out += ",\n          \"host\": \"" + std::string(p.host[0] ? p.host : p.sni) + "\"";
            }
            if (p.mode[0]) {
                out += ",\n          \"mode\": \"" + std::string(p.mode) + "\"";
            }
            if (p.extra[0]) {
                out += ",\n          \"extra\": " + std::string(p.extra);
            }
            out += "\n        }";
        }

        std::string sec = p.security[0] ? p.security : "none";
        if (strcmp(p.protocol, "https") == 0 && sec == "none") sec = "tls";

        out += ",\n        \"security\": \"" + sec + "\"";
        if (sec == "reality") {
            out += ",\n        \"realitySettings\": {\n";
            out += "          \"serverName\": \"" + std::string(p.sni[0] ? p.sni : p.server) + "\",\n";
            out += "          \"publicKey\": \"" + std::string(p.pbk) + "\"";
            if (p.sid[0]) out += ",\n          \"shortId\": \"" + std::string(p.sid) + "\"";
            if (p.fp[0]) out += ",\n          \"fingerprint\": \"" + std::string(p.fp) + "\"";
            out += "\n        }";
        } else if (sec == "tls") {
            out += ",\n        \"tlsSettings\": {\n";
            out += "          \"serverName\": \"" + std::string(p.sni[0] ? p.sni : p.server) + "\"";
            if (p.fp[0]) out += ",\n          \"fingerprint\": \"" + std::string(p.fp) + "\"";
            if (p.alpn[0]) {
                out += ",\n          \"alpn\": [";
                std::string alpn_str = p.alpn;
                size_t s = 0;
                bool first_a = true;
                while (s < alpn_str.length()) {
                    size_t c = alpn_str.find(',', s);
                    if (c == std::string::npos) c = alpn_str.length();
                    if (!first_a) out += ", ";
                    out += "\"" + alpn_str.substr(s, c - s) + "\"";
                    first_a = false;
                    s = c + 1;
                }
                out += "]";
            }
            out += "\n        }";
        }

        out += "\n      }\n    }";
    }

    if (!first_out) out += ",\n";
    out += "    {\n      \"tag\": \"direct\",\n      \"protocol\": \"freedom\"\n    },\n";
    out += "    {\n      \"tag\": \"block\",\n      \"protocol\": \"blackhole\"\n    }\n";
    out += "  ]";

    if (!remarks.empty()) {
        out += ",\n  \"remarks\": \"" + sanitize_json(remarks) + "\"";
    }

    out += "\n}\n";
    return out;
}

std::string gen_v2ray(const std::vector<Proxy>& proxies) {
    std::string out = "";
    for (const auto& p : proxies) {
        if (!p.protocol[0]) continue;
        if (strcmp(p.protocol, "vless") == 0 || strcmp(p.protocol, "trojan") == 0) {
            std::string uri = std::string(p.protocol) + "://" + p.uuid + "@" + p.server + ":" + std::to_string(p.port) + "?";
            if (strcmp(p.protocol, "vless") == 0) uri += "encryption=none&";
            
            std::string net = p.type[0] ? p.type : "tcp";
            if (net == "httpupgrade") net = "ws";
            uri += "type=" + net + "&";

            if (p.security[0]) uri += "security=" + std::string(p.security) + "&";
            if (p.flow[0]) uri += "flow=" + std::string(p.flow) + "&";
            if (p.sni[0]) uri += "sni=" + std::string(p.sni) + "&";
            if (p.fp[0]) uri += "fp=" + std::string(p.fp) + "&";
            if (p.pbk[0]) uri += "pbk=" + std::string(p.pbk) + "&";
            if (p.sid[0]) uri += "sid=" + std::string(p.sid) + "&";
            if (p.host[0]) uri += "host=" + std::string(url_encode(p.host)) + "&";

            if (net == "grpc") {
                uri += "serviceName=" + std::string(url_encode(p.path)) + "&";
                uri += "mode=" + std::string(p.mode[0] ? p.mode : "gun") + "&";
            } else if (p.path[0]) {
                uri += "path=" + std::string(url_encode(p.path)) + "&";
            }

            if (p.alpn[0]) uri += "alpn=" + std::string(url_encode(p.alpn)) + "&";
            if (p.extra[0]) uri += "extra=" + std::string(url_encode(p.extra)) + "&";
            
            if (uri.back() == '&' || uri.back() == '?') uri.pop_back();
            
            uri += "#" + std::string(url_encode(p.name));
            out += uri + "\n";
        }
        else if (strcmp(p.protocol, "shadowsocks") == 0 || strcmp(p.protocol, "ss") == 0) {
            std::string userinfo = std::string(p.cipher[0] ? p.cipher : "aes-128-gcm") + ":" + std::string(p.uuid);
            std::string uri = "ss://" + base64_encode(userinfo) + "@" + std::string(p.server) + ":" + std::to_string(p.port);
            uri += "#" + std::string(url_encode(p.name));
            out += uri + "\n";
        }
        else if (strcmp(p.protocol, "vmess") == 0) {
            std::string json = "{\"v\":\"2\",\"ps\":\"" + std::string(p.name) + "\",\"add\":\"" + std::string(p.server) + "\",\"port\":\"" + std::to_string(p.port) + "\",\"id\":\"" + std::string(p.uuid) + "\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"" + std::string(p.type[0] ? p.type : "tcp") + "\",\"type\":\"none\",\"host\":\"" + std::string(p.host) + "\",\"path\":\"" + std::string(p.path) + "\",\"tls\":\"" + std::string(p.security[0] ? p.security : "") + "\",\"sni\":\"" + std::string(p.sni) + "\",\"alpn\":\"" + std::string(p.alpn) + "\"}";
            out += "vmess://" + base64_encode(json) + "\n";
        }
        else if (strcmp(p.protocol, "hysteria2") == 0 || strcmp(p.protocol, "hy2") == 0) {
            std::string uri = "hysteria2://" + std::string(p.uuid) + "@" + p.server + ":" + std::to_string(p.port) + "?";
            if (p.sni[0]) uri += "sni=" + std::string(p.sni) + "&";
            if (p.obfs[0]) uri += "obfs=" + std::string(p.obfs) + "&";
            if (p.obfs_pass[0]) uri += "obfs-password=" + std::string(p.obfs_pass) + "&";
            if (uri.back() == '&' || uri.back() == '?') uri.pop_back();
            uri += "#" + std::string(url_encode(p.name));
            out += uri + "\n";
        }
        else if (strcmp(p.protocol, "hysteria") == 0) {
            std::string uri = "hysteria://" + std::string(p.uuid) + "@" + p.server + ":" + std::to_string(p.port) + "?";
            if (p.sni[0]) uri += "peer=" + std::string(p.sni) + "&";
            if (p.obfs[0]) uri += "obfs=" + std::string(p.obfs) + "&";
            if (p.obfs_pass[0]) uri += "obfsParam=" + std::string(p.obfs_pass) + "&";
            if (p.up[0]) uri += "upmbps=" + std::string(p.up) + "&";
            if (p.down[0]) uri += "downmbps=" + std::string(p.down) + "&";
            if (p.alpn[0]) uri += "alpn=" + std::string(p.alpn) + "&";
            if (uri.back() == '&' || uri.back() == '?') uri.pop_back();
            uri += "#" + std::string(url_encode(p.name));
            out += uri + "\n";
        }
    }
    return base64_encode(out);
}
