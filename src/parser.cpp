#include "parser.h"
#include "utils.h"
#include <string.h>

Proxy parse_uri(const std::string& uri) {
    Proxy p = {0};
    size_t scheme_pos = uri.find("://");
    if (scheme_pos == std::string::npos) return p;
    std::string scheme = uri.substr(0, scheme_pos);
    strcpy(p.protocol, scheme.c_str());

    if (scheme == "vless" || scheme == "trojan" || scheme == "hysteria2" || scheme == "hy2" || scheme == "hysteria") {
        if (scheme == "hy2") strcpy(p.protocol, "hysteria2");
        size_t at_pos = uri.find('@', scheme_pos + 3);
        size_t hostport_start = scheme_pos + 3;
        if (at_pos != std::string::npos) {
            strcpy(p.uuid, uri.substr(scheme_pos + 3, at_pos - (scheme_pos + 3)).c_str());
            hostport_start = at_pos + 1;
        }

        size_t q_pos = uri.find('?', hostport_start);
        size_t hash_pos = uri.find('#', hostport_start);
        if (hash_pos == std::string::npos) hash_pos = uri.length();
        size_t hostport_end = (q_pos != std::string::npos && q_pos < hash_pos) ? q_pos : hash_pos;

        std::string hostport = uri.substr(hostport_start, hostport_end - hostport_start);
        size_t colon_pos = hostport.find(':');
        if (colon_pos != std::string::npos) {
            strcpy(p.server, hostport.substr(0, colon_pos).c_str());
            p.port = std::stoi(hostport.substr(colon_pos + 1));
        }

        if (hash_pos < uri.length()) {
            strcpy(p.name, url_decode(uri.substr(hash_pos + 1)).c_str());
        }

        if (q_pos != std::string::npos && q_pos < hash_pos) {
            std::string qs = uri.substr(q_pos + 1, hash_pos - (q_pos + 1));
            size_t start = 0;
            while (start < qs.length()) {
                size_t amp = qs.find('&', start);
                if (amp == std::string::npos) amp = qs.length();
                std::string kv = qs.substr(start, amp - start);
                size_t eq = kv.find('=');
                if (eq != std::string::npos) {
                    std::string k = kv.substr(0, eq);
                    std::string v = url_decode(kv.substr(eq + 1));
                    while (!v.empty() && (v.back() == '\r' || v.back() == '\n' || v.back() == ' ')) v.pop_back();

                    if (k == "type") strcpy(p.type, v.c_str());
                    else if (k == "security") strcpy(p.security, v.c_str());
                    else if (k == "sni" || k == "peer") strcpy(p.sni, v.c_str());
                    else if (k == "fp") strcpy(p.fp, v.c_str());
                    else if (k == "pbk") strcpy(p.pbk, v.c_str());
                    else if (k == "sid") strcpy(p.sid, v.c_str());
                    else if (k == "flow") strcpy(p.flow, v.c_str());
                    else if (k == "path") strcpy(p.path, v.c_str());
                    else if (k == "host") strcpy(p.host, v.c_str());
                    else if (k == "alpn") strcpy(p.alpn, v.c_str());
                    else if (k == "serviceName") strcpy(p.path, v.c_str());
                    else if (k == "mode") strcpy(p.mode, v.c_str());
                    else if (k == "encryption") strcpy(p.cipher, v.c_str());
                    else if (k == "headerType") strcpy(p.type, v.c_str());
                    else if (k == "obfs") strcpy(p.obfs, v.c_str());
                    else if (k == "obfs-password" || k == "obfs-param" || k == "obfsParam" || k == "obfsparam") strcpy(p.obfs_pass, v.c_str());
                    else if (k == "up" || k == "upmbps") strcpy(p.up, v.c_str());
                    else if (k == "down" || k == "downmbps") strcpy(p.down, v.c_str());
                    else if (k == "auth") strcpy(p.uuid, v.c_str());
                    else if (k == "extra") {
                        strncpy(p.extra, v.c_str(), sizeof(p.extra) - 1);
                    }
                    else if (k != "type" && k != "security" && k != "sni" && k != "peer" && k != "fp" && k != "pbk" && k != "sid" && k != "host" && k != "path" && k != "alpn" && k != "serviceName" && k != "mode" && k != "flow" && k != "uuid" && k != "port" && k != "name" && k != "encryption" && k != "headerType" && k != "obfs" && k != "obfs-password" && k != "obfs-param" && k != "obfsParam" && k != "obfsparam" && k != "up" && k != "upmbps" && k != "down" && k != "downmbps" && k != "auth") {
                        std::string kebab;
                        for (char c : k) {
                            if (isupper(c)) { kebab += '-'; kebab += tolower(c); }
                            else kebab += c;
                        }
                        std::string v_json;
                        if (v == "true" || v == "false" || (v.length() > 0 && v.find_first_not_of("0123456789-") == std::string::npos)) {
                            v_json = v;
                        } else {
                            v_json = "\"" + sanitize_json(v) + "\"";
                        }
                        
                        if (p.extra[0] == '\0') {
                            strcpy(p.extra, "{");
                        } else {
                            p.extra[strlen(p.extra) - 1] = ',';
                        }
                        std::string kv_json = "\"" + kebab + "\":" + v_json + "}";
                        strncat(p.extra, kv_json.c_str(), sizeof(p.extra) - strlen(p.extra) - 1);
                    }
                }
                start = amp + 1;
            }
        }
    } else if (scheme == "vmess") {
        std::string b64 = uri.substr(scheme_pos + 3);
        std::string jstr = base64_decode(b64);
        auto get_json_str = [&](const std::string& key) {
            size_t kp = jstr.find("\"" + key + "\":");
            if (kp == std::string::npos) return std::string("");
            size_t q1 = jstr.find("\"", kp + key.length() + 2);
            if (q1 == std::string::npos) return std::string("");
            size_t q2 = jstr.find("\"", q1 + 1);
            if (q2 == std::string::npos) return std::string("");
            return jstr.substr(q1 + 1, q2 - q1 - 1);
        };
        auto get_json_int = [&](const std::string& key) {
            size_t kp = jstr.find("\"" + key + "\":");
            if (kp == std::string::npos) return 0;
            size_t st = kp + key.length() + 2;
            while (st < jstr.length() && (jstr[st] == ' ' || jstr[st] == ':')) st++;
            int v = 0;
            while (st < jstr.length() && isdigit(jstr[st])) {
                v = v * 10 + (jstr[st] - '0');
                st++;
            }
            return v;
        };
        strcpy(p.name, get_json_str("ps").c_str());
        strcpy(p.server, get_json_str("add").c_str());
        p.port = get_json_int("port");
        if (p.port == 0) {
            std::string ps = get_json_str("port");
            if (!ps.empty()) p.port = std::stoi(ps);
        }
        strcpy(p.uuid, get_json_str("id").c_str());
        strcpy(p.type, get_json_str("net").c_str());
        strcpy(p.security, get_json_str("tls").c_str());
        strcpy(p.path, get_json_str("path").c_str());
        strcpy(p.host, get_json_str("host").c_str());
        strcpy(p.sni, get_json_str("sni").c_str());
        if (p.security[0] == 0 && get_json_str("tls") == "tls") strcpy(p.security, "tls");
    }
    return p;
}

Proxy parse_xray_json(const std::string& obj) {
    Proxy p = {0};
    if (obj.find("\"outbounds\"") == std::string::npos) return p;
    
    std::string remarks = json_extract_string(obj, "remarks");
    strcpy(p.name, url_decode(remarks).c_str());
    
    size_t proxy_pos = obj.find("\"tag\": \"proxy\"");
    if (proxy_pos == std::string::npos) proxy_pos = obj.find("\"tag\":\"proxy\"");
    if (proxy_pos == std::string::npos) return p;
    
    size_t start = obj.rfind("{", proxy_pos);
    if (start == std::string::npos) return p;
    int depth = 0;
    size_t end = start;
    for (size_t i = start; i < obj.length(); i++) {
        if (obj[i] == '{') depth++;
        else if (obj[i] == '}') {
            depth--;
            if (depth == 0) { end = i; break; }
        }
    }
    std::string outbound = obj.substr(start, end - start + 1);
    
    std::string proto = json_extract_string(outbound, "protocol");
    if (proto == "hysteria" && obj.find("\"version\": 2") != std::string::npos) proto = "hysteria2";
    else if (proto == "hysteria" && json_extract_int(outbound, "version") == 2) proto = "hysteria2";
    strcpy(p.protocol, proto.c_str());
    
    strcpy(p.server, json_extract_string(outbound, "address").c_str());
    p.port = json_extract_int(outbound, "port");
    
    std::string id = json_extract_string(outbound, "id");
    if (id.empty()) id = json_extract_string(outbound, "auth");
    if (id.empty()) id = json_extract_string(outbound, "password");
    strcpy(p.uuid, id.c_str());
    
    strcpy(p.flow, json_extract_string(outbound, "flow").c_str());
    strcpy(p.type, json_extract_string(outbound, "network").c_str());
    strcpy(p.security, json_extract_string(outbound, "security").c_str());
    strcpy(p.sni, json_extract_string(outbound, "serverName").c_str());
    strcpy(p.fp, json_extract_string(outbound, "fingerprint").c_str());
    strcpy(p.pbk, json_extract_string(outbound, "publicKey").c_str());
    strcpy(p.sid, json_extract_string(outbound, "shortId").c_str());
    strcpy(p.path, json_extract_string(outbound, "path").c_str());
    if (p.path[0] == '\0') strcpy(p.path, json_extract_string(outbound, "serviceName").c_str());
    strcpy(p.host, json_extract_string(outbound, "host").c_str());
    
    size_t alpn_pos = outbound.find("\"alpn\"");
    if (alpn_pos != std::string::npos) {
        size_t b_start = outbound.find("[", alpn_pos);
        size_t b_end = outbound.find("]", b_start);
        if (b_start != std::string::npos && b_end != std::string::npos) {
            std::string alpn_arr = outbound.substr(b_start, b_end - b_start);
            size_t q1 = alpn_arr.find("\"");
            if (q1 != std::string::npos) {
                size_t q2 = alpn_arr.find("\"", q1 + 1);
                if (q2 != std::string::npos) {
                    strcpy(p.alpn, alpn_arr.substr(q1 + 1, q2 - q1 - 1).c_str());
                }
            }
        }
    }
    
    size_t extra_pos = outbound.find("\"extra\"");
    if (extra_pos != std::string::npos) {
        size_t b_start = outbound.find("{", extra_pos);
        if (b_start != std::string::npos) {
            int d = 0;
            size_t b_end = b_start;
            for (size_t i = b_start; i < outbound.length(); i++) {
                if (outbound[i] == '{') d++;
                else if (outbound[i] == '}') {
                    d--;
                    if (d == 0) { b_end = i; break; }
                }
            }
            if (b_end > b_start) {
                std::string extra_obj = outbound.substr(b_start, b_end - b_start + 1);
                strncpy(p.extra, extra_obj.c_str(), sizeof(p.extra) - 1);
            }
        }
    }
    
    return p;
}

std::vector<Proxy> parse_proxies(const std::string& decoded) {
    std::vector<Proxy> proxies;
    
    size_t first_char = decoded.find_first_not_of(" \t\r\n");
    if (first_char != std::string::npos && (decoded[first_char] == '[' || decoded[first_char] == '{')) {
        size_t start = first_char;
        while ((start = decoded.find("{", start)) != std::string::npos) {
            int depth = 0;
            size_t end = start;
            for (size_t i = start; i < decoded.length(); i++) {
                if (decoded[i] == '{') depth++;
                else if (decoded[i] == '}') {
                    depth--;
                    if (depth == 0) { end = i; break; }
                }
            }
            if (depth == 0 && end > start) {
                std::string obj = decoded.substr(start, end - start + 1);
                Proxy p = parse_xray_json(obj);
                if (p.protocol[0] != '\0') {
                    proxies.push_back(p);
                }
                start = end + 1;
            } else {
                break;
            }
        }
        if (!proxies.empty()) return proxies;
    }

    size_t start = 0;
    while (start < decoded.length()) {
        size_t nl = decoded.find('\n', start);
        if (nl == std::string::npos) nl = decoded.length();
        std::string line = decoded.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (!line.empty()) {
            Proxy p = parse_uri(line);
            if (p.protocol[0]) proxies.push_back(p);
        }
        start = nl + 1;
    }
    return proxies;
}
