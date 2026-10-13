#include "generator.h"
#include "parser.h"
#include "utils.h"
#include <cassert>
#include <cstring>
#include <string_view>

void test_xray_mixed_links() {
    assert(gen_xray_mixed({}).empty());
    assert(gen_xray_mixed({Proxy{}}).empty());

    const std::vector<std::string> protocols = {
        "vless", "trojan", "vmess", "ss", "shadowsocks", "hysteria", "hysteria2", "hy2"
    };
    std::vector<Proxy> proxies;
    for (const auto& protocol : protocols) {
        Proxy p{};
        strcpy(p.protocol, protocol.c_str());
        strcpy(p.name, "Test node");
        strcpy(p.server, "192.0.2.10");
        strcpy(p.uuid, "00000000-0000-0000-0000-000000000001");
        p.port = 443;
        proxies.push_back(p);
        std::string scheme = protocol;
        if (scheme == "shadowsocks") scheme = "ss";
        if (scheme == "hy2") scheme = "hysteria2";
        std::string mixed = gen_xray_mixed({p});
        assert(mixed.starts_with(scheme + "://"));
        assert(mixed.ends_with("\n"));
        assert(mixed == base64_decode(gen_v2ray({p})));
    }
    // No balancers means a plain link list, not an empty JSON array or Base64.
    std::string mixed = gen_xray_mixed(proxies);
    assert(mixed == base64_decode(gen_v2ray(proxies)));
    assert(mixed.find('{') == std::string::npos);
    std::println("test_xray_mixed_links passed.");
}

void test_xray_mixed_balancers() {
    Proxy p{};
    strcpy(p.protocol, "vless");
    strcpy(p.name, "Server Germany");
    strcpy(p.server, "192.0.2.1");
    strcpy(p.uuid, "00000000-0000-0000-0000-000000000001");
    strcpy(p.security, "reality");
    strcpy(p.sni, "example.com");
    strcpy(p.pbk, "example-key-1");
    p.port = 443;
    std::vector<Proxy> proxies{p};
    strcpy(p.name, "Server Netherlands");
    strcpy(p.server, "192.0.2.2");
    proxies.push_back(p);

    Balancer b{};
    strcpy(b.name, "Auto Europe");
    b.proxies = {"Server Germany", "Server Netherlands"};
    std::vector<Balancer> balancers{b};
    Rule r{};
    strcpy(r.outbound, "block");
    r.protocols = {"bittorrent"};
    std::vector<Rule> rules{r};

    // Mixed output keeps only balancers as JSON; member nodes still get links.
    std::string xray_jsons = gen_xray_jsons(proxies, balancers, rules);
    std::string mixed = gen_xray_mixed(proxies, balancers, rules);
    std::string links = base64_decode(gen_v2ray(proxies));
    assert(!links.empty());
    assert(mixed.ends_with(links));
    assert(!mixed.starts_with("["));
    std::string balancer_json = mixed.substr(0, mixed.size() - links.size() - 1);
    assert(xray_jsons.starts_with("[\n" + balancer_json + ",\n"));
    assert(balancer_json.contains("\"balancers\":"));
    assert(balancer_json.contains("\"burstObservatory\":"));
    assert(balancer_json.contains("bittorrent"));
    assert(balancer_json.contains("192.0.2.1"));
    assert(balancer_json.contains("192.0.2.2"));
    assert(!balancer_json.contains("\"remarks\": \"Server Germany\""));
    assert(links.contains("#Server%20Germany\n"));
    assert(links.contains("#Server%20Netherlands\n"));

    // Multiple balancers are separate objects, without array commas.
    balancers.push_back(b);
    assert(gen_xray_mixed(proxies, balancers, rules) ==
           balancer_json + "\n" + balancer_json + "\n" + links);

    // A standalone node is linked but is not added to an explicit balancer.
    strcpy(p.name, "Standalone");
    strcpy(p.server, "192.0.2.3");
    proxies.push_back(p);
    mixed = gen_xray_mixed(proxies, {b}, rules);
    assert(mixed.starts_with(balancer_json + "\n"));
    assert(mixed.ends_with(base64_decode(gen_v2ray(proxies))));
    assert(mixed.contains("#Standalone\n"));

    // Preserve xray-jsons' fallback to all nodes for an empty member list.
    b.proxies.clear();
    mixed = gen_xray_mixed(proxies, {b});
    assert(mixed.contains("\"address\": \"192.0.2.3\""));
    // No standalone proxies: still emit a complete JSON object, not an array.
    mixed = gen_xray_mixed({}, {b});
    assert(mixed.starts_with("  {\n"));
    assert(mixed.ends_with("  }\n"));
    assert(mixed.contains("\"remarks\": \"Auto Europe\""));
    std::println("test_xray_mixed_balancers passed.");
}

void test_xhttp_share_links() {
    // This combination reproduces the reported Xray validation error if mode
    // is lost: header placement is only valid in packet-up mode.
    const std::string_view config = R"json({
      "remarks": "XHTTP packet up",
      "outbounds": [{
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": "192.0.2.10", "port": 443,
          "users": [{"id": "00000000-0000-0000-0000-000000000001"}]}]},
        "streamSettings": {
          "network": "xhttp", "security": "tls",
          "tlsSettings": {"serverName": "example.com"},
          "xhttpSettings": {
            "host": "example.com", "path": "/upload?a=1&b=2",
            "mode": "packet-up",
            "extra": {"uplinkDataPlacement":"header","uplinkDataKey":"X-Data"}
          }
        }
      }]
    })json";
    Proxy p = parse_xray_json(config);
    assert(std::string_view(p.type) == "xhttp");
    assert(std::string_view(p.mode) == "packet-up");
    assert(std::string_view(p.extra).contains("\"uplinkDataPlacement\":\"header\""));

    for (const char* protocol : {"vless", "trojan"}) {
        strcpy(p.protocol, protocol);
        for (const char* mode : {"packet-up", "stream-up", "stream-one", "auto"}) {
            strcpy(p.mode, mode);
            std::string link = gen_xray_mixed({p});
            assert(link.contains("type=xhttp&"));
            assert(link.contains(std::string("mode=") + mode + "&"));
            assert(link.contains("path=%2Fupload%3Fa%3D1%26b%3D2&"));
            assert(link.contains("extra=" + url_encode(p.extra)));
            // The same fix must reach the Base64 xray/v2ray targets.
            assert(link == base64_decode(gen_v2ray({p})));
            link.pop_back(); // Strip the subscription line separator.
            Proxy roundtrip = parse_uri(link);
            assert(std::string_view(roundtrip.mode) == mode);
            assert(std::string_view(roundtrip.extra) == p.extra);
            assert(std::string_view(roundtrip.path) == p.path);
            assert(std::string_view(roundtrip.host) == p.host);
            assert(std::string_view(roundtrip.sni) == p.sni);
            if (std::string_view(mode) == "packet-up") {
                std::string json = gen_xray({roundtrip});
                assert(json.contains("\"mode\": \"packet-up\""));
                assert(json.contains("\"uplinkDataPlacement\":\"header\""));
            }
        }
    }

    // Mode must not depend on whether the optional path was supplied.
    p.path[0] = '\0';
    strcpy(p.mode, "packet-up");
    assert(gen_xray_mixed({p}).contains("mode=packet-up&"));
    // Do not invent a mode for nodes that leave it unspecified.
    p.mode[0] = '\0';
    assert(!gen_xray_mixed({p}).contains("mode="));

    // Leave the existing gRPC mode/serviceName handling intact.
    strcpy(p.type, "grpc");
    strcpy(p.path, "grpc-service");
    p.extra[0] = '\0';
    assert(gen_xray_mixed({p}).contains("serviceName=grpc-service&mode=gun"));
    strcpy(p.mode, "multi");
    assert(gen_xray_mixed({p}).contains("serviceName=grpc-service&mode=multi"));
    std::println("test_xhttp_share_links passed.");
}

int main() {
    test_xray_mixed_links();
    test_xray_mixed_balancers();
    test_xhttp_share_links();
}
