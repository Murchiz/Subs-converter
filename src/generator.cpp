#include "generator.h"
#include "utils.h"
#include <string.h>
std::string gen_clash(const std::vector<Proxy>& proxies) {
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
        }

        std::string net = p.type;
        if (strcmp(p.type, "httpupgrade") == 0) net = "ws";
        if (strcmp(p.protocol, "hysteria2") != 0 && p.type[0]) out += "    network: " + net + "\n";

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
            if (p.extra[0]) out += std::string(p.extra);
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
           "rules:\n"
           "  - MATCH,Proxy\n";
    return out;
}
std::string gen_singbox(const std::vector<Proxy>& proxies) {
    std::string out = "{\n"
                      "  \"dns\": {\"strategy\":\"ipv4_only\",\"rules\":[{\"server\":\"remote\",\"query_type\":[\"A\",\"AAAA\"]}],\"servers\":[{\"tag\":\"cf-dns\",\"type\":\"tls\",\"server\":\"1.1.1.1\"},{\"tag\":\"local\",\"type\":\"tcp\",\"server\":\"1.1.1.1\"},{\"tag\":\"remote\",\"type\":\"fakeip\",\"inet4_range\":\"198.18.0.0/15\",\"inet6_range\":\"fc00::/18\"}]},\n"
                      "  \"log\": {\"level\":\"info\",\"disabled\":false,\"timestamp\":true},\n"
                      "  \"route\": {\"default_domain_resolver\":\"local\",\"rules\":[{\"action\":\"sniff\"},{\"mode\":\"or\",\"type\":\"logical\",\"rules\":[{\"protocol\":\"dns\"},{\"port\":53}],\"action\":\"hijack-dns\"},{\"outbound\":\"direct\",\"ip_is_private\":true}],\"override_android_vpn\":true,\"auto_detect_interface\":true},\n"
                      "  \"inbounds\": [{\"mtu\":9000,\"tag\":\"tun-in\",\"type\":\"tun\",\"stack\":\"mixed\",\"auto_route\":true,\"strict_route\":true,\"address\":[\"172.19.0.1/30\",\"fdfe:dcba:9876::1/126\"],\"endpoint_independent_nat\":true},{\"tag\":\"mixed-in\",\"type\":\"mixed\",\"users\":[],\"listen\":\"127.0.0.1\",\"listen_port\":2412,\"set_system_proxy\":false}],\n"
                      "  \"outbounds\": [\n";
    std::string proxy_tags = "";
    std::string outbounds_arr = "";
    bool first = true;
    for (size_t i = 0; i < proxies.size(); i++) {
        const auto& p = proxies[i];
        if (!p.protocol[0]) continue;
        if (strcmp(p.type, "xhttp") == 0) continue; // Filter out xhttp
        if (!p.protocol[0]) continue;
        if (strcmp(p.type, "xhttp") == 0) continue; // Filter out xhttp
        
        if (!first) outbounds_arr += ",\n";
        first = false;
        
        std::string s_name = sanitize_json(p.name);
        proxy_tags += "\"" + s_name + "\",";
        
        outbounds_arr += "    {\n";
        outbounds_arr += "      \"type\": \"" + std::string(p.protocol) + "\",\n";
        outbounds_arr += "      \"tag\": \"" + s_name + "\",\n";
        outbounds_arr += "      \"server\": \"" + std::string(p.server) + "\",\n";
        outbounds_arr += "      \"server_port\": " + std::to_string(p.port) + ",\n";

        if (strcmp(p.protocol, "vless") == 0 || strcmp(p.protocol, "vmess") == 0) {
            outbounds_arr += "      \"uuid\": \"" + std::string(p.uuid) + "\"";
            if (strcmp(p.protocol, "vmess") == 0) {
                outbounds_arr += ",\n      \"security\": \"auto\"";
            }
            if (strcmp(p.protocol, "vless") == 0 && p.flow[0]) {
                outbounds_arr += ",\n      \"flow\": \"" + std::string(p.flow) + "\"";
            }
        } else if (strcmp(p.protocol, "trojan") == 0) {
            outbounds_arr += "      \"password\": \"" + std::string(p.uuid) + "\"";
        } else if (strcmp(p.protocol, "hysteria2") == 0) {
            outbounds_arr += "      \"password\": \"" + std::string(p.uuid) + "\"";
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
        }

        if (strcmp(p.protocol, "hysteria2") != 0 && (strcmp(p.security, "tls") == 0 || strcmp(p.security, "reality") == 0)) {
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

        if (strcmp(p.protocol, "hysteria2") != 0 && p.type[0] && strcmp(p.type, "tcp") != 0) {
            outbounds_arr += ",\n      \"transport\": {\n";
            outbounds_arr += "        \"type\": \"" + std::string(p.type) + "\"";
            if (strcmp(p.type, "ws") == 0 || strcmp(p.type, "httpupgrade") == 0 || strcmp(p.type, "xhttp") == 0) {
                outbounds_arr += ",\n        \"path\": \"" + std::string(p.path[0] ? p.path : "/") + "\"";
                outbounds_arr += ",\n        \"headers\": { \"Host\": \"" + std::string(p.host[0] ? p.host : (p.sni[0] ? p.sni : p.server)) + "\" }";
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
