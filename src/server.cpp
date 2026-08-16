#include "server.h"
#include "utils.h"
#include "parser.h"
#include "generator.h"
#include <thread>
#include <cstdio>
#include <cstring>
#include <cctype>

void copy_limited(char *dst, int cap, const char *src) {
    if (!dst || cap <= 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    strncpy_s(dst, cap, src, cap - 1);
}

static bool query_header(HINTERNET req, const wchar_t *name, char *out, int cap) {
    if (!out || cap <= 0) return false;
    out[0] = '\0';

    wchar_t wbuf[2048] = {0};
    DWORD wlen = sizeof(wbuf);
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_CUSTOM, name, wbuf, &wlen, WINHTTP_NO_HEADER_INDEX)) {
        return false;
    }

    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, cap, NULL, NULL);
    out[cap - 1] = '\0';
    return out[0] != '\0';
}

static bool query_content_type(HINTERNET req, char *out, int cap) {
    if (!out || cap <= 0) return false;
    out[0] = '\0';

    wchar_t wbuf[256] = {0};
    DWORD wlen = sizeof(wbuf);
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX, wbuf, &wlen, WINHTTP_NO_HEADER_INDEX)) {
        return false;
    }

    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, cap, NULL, NULL);
    out[cap - 1] = '\0';
    return out[0] != '\0';
}

static void merge_metadata(SubMetadata& dst, const SubMetadata& src) {
    if (!dst.userinfo[0] && src.userinfo[0]) copy_limited(dst.userinfo, sizeof(dst.userinfo), src.userinfo);
    if (!dst.interval[0] && src.interval[0]) copy_limited(dst.interval, sizeof(dst.interval), src.interval);
    if (!dst.disposition[0] && src.disposition[0]) copy_limited(dst.disposition, sizeof(dst.disposition), src.disposition);
    if (!dst.profile_title[0] && src.profile_title[0]) copy_limited(dst.profile_title, sizeof(dst.profile_title), src.profile_title);
    if (!dst.announce[0] && src.announce[0]) copy_limited(dst.announce, sizeof(dst.announce), src.announce);
    if (!dst.profile_web_page_url[0] && src.profile_web_page_url[0]) copy_limited(dst.profile_web_page_url, sizeof(dst.profile_web_page_url), src.profile_web_page_url);
    if (!dst.support_url[0] && src.support_url[0]) copy_limited(dst.support_url, sizeof(dst.support_url), src.support_url);
    if (!dst.refill_date[0] && src.refill_date[0]) copy_limited(dst.refill_date, sizeof(dst.refill_date), src.refill_date);
    if (!dst.content_type[0] && src.content_type[0]) copy_limited(dst.content_type, sizeof(dst.content_type), src.content_type);
}

static std::string header_safe(const char *value) {
    std::string out;
    if (!value) return out;
    for (const char *p = value; *p; p++) {
        out += (*p == '\r' || *p == '\n') ? ' ' : *p;
    }
    return out;
}

static std::string lower_copy(const std::string& value) {
    std::string out = value;
    for (char& c : out) c = (char)tolower((unsigned char)c);
    return out;
}

static bool contains_ci(const std::string& value, const char *needle) {
    return lower_copy(value).find(lower_copy(needle)) != std::string::npos;
}

static std::string request_header(const std::string& req, const char *name) {
    std::string wanted = lower_copy(name);
    size_t start = 0;
    while (start < req.length()) {
        size_t end = req.find('\n', start);
        if (end == std::string::npos) end = req.length();
        std::string line = req.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();

        size_t colon = line.find(':');
        if (colon != std::string::npos && lower_copy(line.substr(0, colon)) == wanted) {
            size_t value_start = line.find_first_not_of(" \t", colon + 1);
            return value_start == std::string::npos ? "" : line.substr(value_start);
        }
        start = end + 1;
    }
    return "";
}

static std::string target_from_user_agent(const std::string& ua) {
    if (contains_ci(ua, "clash")) return "clash";
    if (contains_ci(ua, "sing-box") || contains_ci(ua, "singbox")) return "singbox";
    if (contains_ci(ua, "v2ray") || contains_ci(ua, "xray") ||
        contains_ci(ua, "nekobox") || contains_ci(ua, "nekoray") ||
        contains_ci(ua, "happ") || contains_ci(ua, "hiddify") ||
        contains_ci(ua, "streisand") || contains_ci(ua, "shadowrocket")) {
        return "v2ray";
    }
    return "";
}

static void append_header(std::string& headers, const char *name, const char *value) {
    if (!value || !value[0]) return;
    headers += name;
    headers += ": ";
    headers += header_safe(value);
    headers += "\r\n";
}

static std::string quoted_filename(const char *name) {
    std::string out;
    for (const char *p = name; p && *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c >= 0x7f) continue;
        if (*p == '"' || *p == '\\') out += '_';
        else out += *p;
    }
    return out.empty() ? "subscription" : out;
}

static void apply_route_name(SubMetadata& meta, const char *name) {
    if (!name || !name[0]) return;

    std::string title = "base64:" + base64_encode(name);
    copy_limited(meta.profile_title, sizeof(meta.profile_title), title.c_str());

    std::string disp = "attachment; filename=\"" + quoted_filename(name) +
                       "\"; filename*=UTF-8''" + url_encode(name);
    copy_limited(meta.disposition, sizeof(meta.disposition), disp.c_str());
}

static std::string metadata_headers(const SubMetadata& meta) {
    std::string headers;
    append_header(headers, "Subscription-Userinfo", meta.userinfo);
    append_header(headers, "Profile-Update-Interval", meta.interval);
    append_header(headers, "Profile-Title", meta.profile_title);
    append_header(headers, "Announce", meta.announce);
    append_header(headers, "Profile-Web-Page-Url", meta.profile_web_page_url);
    append_header(headers, "Support-Url", meta.support_url);
    append_header(headers, "Subscription-Refill-Date", meta.refill_date);
    append_header(headers, "Content-Disposition", meta.disposition);
    return headers;
}

static const char *converted_content_type(const std::string& target) {
    if (target == "clash") return "text/yaml; charset=utf-8";
    if (target == "singbox" || target == "sing-box" || target == "singbox-pc" || target == "sing-box-pc") return "application/json; charset=utf-8";
    return "text/plain; charset=utf-8";
}

static bool preferred_metadata_source(const std::string& target, const Route& rt, int index, const SubMetadata& meta) {
    std::string ua = (index >= 0 && index < 8) ? rt.user_agents[index] : "";
    if (target == "clash") {
        return contains_ci(ua, "clash") || contains_ci(meta.content_type, "yaml");
    }
    if (target == "v2ray") {
        return contains_ci(meta.content_type, "text/plain");
    }
    if (target == "singbox" || target == "sing-box" || target == "singbox-pc" || target == "sing-box-pc") {
        return contains_ci(ua, "sing") || contains_ci(meta.content_type, "json");
    }
    return false;
}

static void merge_metadata_for_target(SubMetadata& dst, const SubMetadata& src, bool preferred, bool& have_preferred) {
    if (preferred && !have_preferred) {
        SubMetadata old = dst;
        dst = src;
        merge_metadata(dst, old);
        have_preferred = true;
        return;
    }
    if (!have_preferred || preferred) {
        merge_metadata(dst, src);
    }
}

int fetch_url(const Route *rt, char *buf, int cap, const wchar_t* custom_ua, int url_index,
              SubMetadata *out_meta) {
    HINTERNET hS = NULL, hC = NULL, hR = NULL;
    int total = -1;
    char full_url[4096];
    std::wstring object_name;

    if (out_meta) memset(out_meta, 0, sizeof(*out_meta));

    copy_limited(full_url, sizeof(full_url), rt->urls[url_index]);

    wchar_t wurl[4096];
    MultiByteToWideChar(CP_UTF8, 0, full_url, -1, wurl, 4096);

    URL_COMPONENTS uc;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.dwHostNameLength = -1;
    uc.dwUrlPathLength = -1;
    uc.dwExtraInfoLength = -1;

    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        return -1;
    }

    wchar_t host[256] = { 0 };
    wcsncpy_s(host, 256, uc.lpszHostName, uc.dwHostNameLength);

    const wchar_t* ua = custom_ua;
    wchar_t wua[128] = {0};
    if (!ua && rt && rt->user_agents[url_index][0]) {
        MultiByteToWideChar(CP_UTF8, 0, rt->user_agents[url_index], -1, wua, 128);
        ua = wua;
    }
    if (!ua) ua = UA_WIDE;

    hS = WinHttpOpen(ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) goto out;

    WinHttpSetTimeouts(hS, UP_TIMEOUT, UP_TIMEOUT, UP_TIMEOUT, UP_TIMEOUT);

    hC = WinHttpConnect(hS, host, uc.nPort, 0);
    if (!hC) goto out;

    if (uc.lpszUrlPath && uc.dwUrlPathLength) {
        object_name.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
    } else {
        object_name = L"/";
    }
    if (uc.lpszExtraInfo && uc.dwExtraInfoLength) {
        object_name.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    }

    hR = WinHttpOpenRequest(hC, L"GET", object_name.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                            (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hR) goto out;

    if (rt->use_hwid) {
        wchar_t hdr[1024], wH[128], wO[64], wV[64], wM[256];
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.hwid, -1, wH, 128);
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.os, -1, wO, 64);
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.ver, -1, wV, 64);
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.model, -1, wM, 256);
        _snwprintf_s(hdr, sizeof(hdr) / sizeof(hdr[0]), _TRUNCATE,
                   L"x-hwid: %s\r\n"
                   L"x-device-os: %s\r\n"
                   L"x-ver-os: %s\r\n"
                   L"x-device-model: %s",
                   wH, wO, wV, wM);
        WinHttpAddRequestHeaders(hR, hdr, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    }

    if (!WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) goto out;
    if (!WinHttpReceiveResponse(hR, NULL)) goto out;

    {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        if (code != 200) { total = -(int)code; goto out; }
    }

    if (out_meta) {
        query_header(hR, L"Subscription-Userinfo", out_meta->userinfo, sizeof(out_meta->userinfo));
        query_header(hR, L"Profile-Update-Interval", out_meta->interval, sizeof(out_meta->interval));
        query_header(hR, L"Content-Disposition", out_meta->disposition, sizeof(out_meta->disposition));
        query_header(hR, L"Profile-Title", out_meta->profile_title, sizeof(out_meta->profile_title));
        query_header(hR, L"Announce", out_meta->announce, sizeof(out_meta->announce));
        query_header(hR, L"Profile-Web-Page-Url", out_meta->profile_web_page_url, sizeof(out_meta->profile_web_page_url));
        query_header(hR, L"Support-Url", out_meta->support_url, sizeof(out_meta->support_url));
        query_header(hR, L"Subscription-Refill-Date", out_meta->refill_date, sizeof(out_meta->refill_date));
        query_content_type(hR, out_meta->content_type, sizeof(out_meta->content_type));
    }

    total = 0;
    for (;;) {
        DWORD avail = 0, got = 0;
        if (!WinHttpQueryDataAvailable(hR, &avail) || !avail) break;
        if (total + (int)avail >= cap) avail = (DWORD)(cap - 1 - total);
        if (!avail) break;
        if (!WinHttpReadData(hR, buf + total, avail, &got)) break;
        total += (int)got;
    }
    buf[total] = '\0';

out:
    if (hR) WinHttpCloseHandle(hR);
    if (hC) WinHttpCloseHandle(hC);
    if (hS) WinHttpCloseHandle(hS);
    return total;
}
static void serve_converted_or_raw(SOCKET c, const Route *source_rt, const std::string& target, int log_port) {
    char *body = (char *)HeapAlloc(GetProcessHeap(), 0, BODY_CAP);
    if (!body) {
        const char *e = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOOM";
        send(c, e, (int)strlen(e), 0);
        return;
    }

    std::string out_payload;
    std::string raw_clash_proxies;
    std::string raw_clash_names;
    std::vector<Proxy> all_proxies;
    std::vector<Rule> all_rules;
    int success_count = 0;

    SubMetadata meta = {0};
    bool have_preferred_meta = false;

    for (int i = 0; i < source_rt->url_count; i++) {
        SubMetadata temp_meta = {0};
        int blen = fetch_url(source_rt, body, BODY_CAP, NULL, i, &temp_meta);
        if (blen >= 0) {
            success_count++;
            if (!target.empty()) {
                merge_metadata_for_target(meta, temp_meta, preferred_metadata_source(target, *source_rt, i, temp_meta), have_preferred_meta);
            } else {
                merge_metadata(meta, temp_meta);
            }

            std::string payload(body, blen);

            if (target == "clash" && payload.find("proxies:") != std::string::npos) {
                // Extract Native Clash YAML proxies
                size_t p_start = payload.find("proxies:");
                if (p_start != std::string::npos) {
                    p_start += 8;
                    if (p_start < payload.length() && payload[p_start] == '\r') p_start++;
                    if (p_start < payload.length() && payload[p_start] == '\n') p_start++;

                    size_t next_section = std::string::npos;
                    size_t search_pos = p_start;
                    while ((search_pos = payload.find('\n', search_pos)) != std::string::npos) {
                        search_pos++;
                        if (search_pos < payload.length() && isalpha((unsigned char)payload[search_pos])) {
                            next_section = search_pos;
                            break;
                        }
                    }
                    size_t p_end = (next_section != std::string::npos) ? next_section : payload.length();
                    std::string block = payload.substr(p_start, p_end - p_start);

                    std::string filtered_block;
                    size_t search_start = 0;
                    while (true) {
                        size_t name_pos = block.find("- name:", search_start);
                        if (name_pos == std::string::npos) break;

                        size_t node_start = name_pos;
                        while (node_start > 0 && (block[node_start - 1] == ' ' || block[node_start - 1] == '\t')) {
                            node_start--;
                        }

                        size_t next_name_pos = block.find("- name:", name_pos + 7);
                        size_t next_node_start = block.length();
                        if (next_name_pos != std::string::npos) {
                            next_node_start = next_name_pos;
                            while (next_node_start > node_start && (block[next_node_start - 1] == ' ' || block[next_node_start - 1] == '\t')) {
                                next_node_start--;
                            }
                        }

                        std::string node_str = block.substr(node_start, next_node_start - node_start);
                        filtered_block += node_str;

                        size_t n_pos = node_str.find("- name:");
                        size_t end_line = node_str.find('\n', n_pos);
                        if (end_line == std::string::npos) end_line = node_str.length();
                        size_t val_start = node_str.find_first_not_of(" \t", n_pos + 7);
                        if (val_start != std::string::npos && val_start < end_line) {
                            size_t val_end = end_line - 1;
                            while (val_end >= val_start && (node_str[val_end] == ' ' || node_str[val_end] == '\t' || node_str[val_end] == '\r' || node_str[val_end] == '\n')) {
                                val_end--;
                            }
                            if (val_start <= val_end) {
                                std::string raw_name = node_str.substr(val_start, val_end - val_start + 1);
                                if (raw_name.length() >= 2 && ((raw_name.front() == '"' && raw_name.back() == '"') ||
                                    (raw_name.front() == '\'' && raw_name.back() == '\''))) {
                                    raw_name = raw_name.substr(1, raw_name.length() - 2);
                                }
                                raw_clash_names += "      - \"" + raw_name + "\"\n";
                            }
                        }

                        search_start = next_name_pos;
                    }
                    raw_clash_proxies += filtered_block;
                }
            } else if (!target.empty()) {
                std::string decoded;
                size_t first_char = payload.find_first_not_of(" \t\r\n");
                if (first_char != std::string::npos && (payload[first_char] == '[' || payload[first_char] == '{')) {
                    decoded = payload;
                } else {
                    decoded = (payload.find("://") != std::string::npos) ? payload : base64_decode(payload);
                }
                auto p = parse_proxies(decoded);
                all_proxies.insert(all_proxies.end(), p.begin(), p.end());
                auto r = parse_xray_rules(decoded);
                all_rules.insert(all_rules.end(), r.begin(), r.end());
            } else {
                if (!out_payload.empty()) out_payload += "\n";
                out_payload.append(body, blen);
            }
        }
    }

    if (success_count > 0) {
        std::string content_type;
        if (target == "clash") {
            out_payload = gen_clash(all_proxies, all_rules);
            if (!raw_clash_proxies.empty()) {
                while (!raw_clash_proxies.empty() && isspace((unsigned char)raw_clash_proxies.back())) {
                    raw_clash_proxies.pop_back();
                }
                raw_clash_proxies += "\n";

                size_t pg = out_payload.find("proxy-groups:");
                if (pg != std::string::npos) {
                    out_payload.insert(pg, raw_clash_proxies);

                    size_t auto_grp = out_payload.find("  - name: Auto\n    type: url-test");
                    if (auto_grp != std::string::npos) {
                        out_payload.insert(auto_grp, raw_clash_names);
                    }

                    size_t rules = out_payload.find("rules:");
                    if (rules != std::string::npos) {
                        out_payload.insert(rules, raw_clash_names);
                    }
                }
            }
            content_type = converted_content_type(target);
        } else if (target == "singbox" || target == "sing-box") {
            out_payload = gen_singbox(all_proxies, "android", all_rules);
            content_type = converted_content_type(target);
        } else if (target == "singbox-pc" || target == "sing-box-pc") {
            out_payload = gen_singbox(all_proxies, "pc", all_rules);
            content_type = converted_content_type(target);
        } else if (!target.empty()) {
            out_payload = gen_v2ray(all_proxies);
            content_type = converted_content_type(target);
        } else {
            content_type = meta.content_type[0] ? header_safe(meta.content_type) : "text/plain; charset=utf-8";
        }

        apply_route_name(meta, source_rt->name);
        std::string extra_hdrs = metadata_headers(meta);

        std::string hdr = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: " + content_type + "\r\n"
                          "Content-Length: " + std::to_string(out_payload.length()) + "\r\n"
                          + extra_hdrs +
                          "Connection: close\r\n\r\n";
        send(c, hdr.c_str(), (int)hdr.length(), 0);
        send(c, out_payload.c_str(), (int)out_payload.length(), 0);
        if (!target.empty()) {
            logm("  [OK] Port %d (target=%s) -> 200 OK (%zu bytes)\n\n", log_port, target.c_str(), out_payload.length());
        } else {
            logm("  [OK] Port %d -> 200 OK (%zu bytes)\n\n", log_port, out_payload.length());
        }
    } else {
        std::string e = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 15\r\nConnection: close\r\n\r\nupstream failed";
        send(c, e.c_str(), (int)e.length(), 0);
        logm("  [FAIL] Port %d -> 502 Upstream Failed\n\n", log_port);
    }
    HeapFree(GetProcessHeap(), 0, body);
}

void handle_subconverter(SOCKET c, const std::string& req) {
    size_t q_pos = req.find('?');
    size_t space_pos = req.find(' ', q_pos);
    if (q_pos == std::string::npos || space_pos == std::string::npos) {
        const char *r = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
        send(c, r, (int)strlen(r), 0);
        return;
    }

    std::string qs = req.substr(q_pos + 1, space_pos - (q_pos + 1));
    std::string target, url;
    size_t start = 0;
    while (start < qs.length()) {
        size_t amp = qs.find('&', start);
        if (amp == std::string::npos) amp = qs.length();
        std::string kv = qs.substr(start, amp - start);
        size_t eq = kv.find('=');
        if (eq != std::string::npos) {
            std::string k = kv.substr(0, eq);
            std::string v = url_decode(kv.substr(eq + 1));
            if (k == "target") target = v;
            else if (k == "url") url = v;
        }
        start = amp + 1;
    }

    if (url.empty()) {
        const char *r = "HTTP/1.1 400 Missing URL\r\nConnection: close\r\n\r\n";
        send(c, r, (int)strlen(r), 0);
        return;
    }

    Route temp_rt = { 0 };
    int internal_port = 0;
    if (url.find("http://127.0.0.1:") == 0) {
        internal_port = atoi(url.c_str() + 17);
    }

    const Route *source_rt = &temp_rt;
    if (internal_port > 0) {
        for (int i = 0; i < g_RouteCount; i++) {
            if (g_Routes[i].local_port == internal_port) {
                source_rt = &g_Routes[i];
                break;
            }
        }
    }
    if (source_rt == &temp_rt) {
        copy_limited(temp_rt.urls[0], sizeof(temp_rt.urls[0]), url.c_str());
        temp_rt.url_count = 1;
    }

    serve_converted_or_raw(c, source_rt, target, 25500);
}

void handle_client(SOCKET c, const Route *rt) {
    DWORD tv = CL_TIMEOUT;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

    char req[2048];
    int n = recv(c, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        closesocket(c);
        return;
    }
    req[n] = '\0';

    if (strncmp(req, "GET ", 4) != 0) {
        const char *r = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(c, r, (int)strlen(r), 0);
        closesocket(c);
        return;
    }

    if (rt->is_subconverter) {
        handle_subconverter(c, req);
        shutdown(c, SD_SEND);
        closesocket(c);
        return;
    }

    logm("  [REQ] Port %d\n", rt->local_port);

    if (rt->is_convert) {
        const Route *source_rt = rt;
        for (int i = 0; i < g_RouteCount; i++) {
            if (!g_Routes[i].is_convert && !g_Routes[i].is_subconverter && g_Routes[i].local_port == rt->base_port) {
                source_rt = &g_Routes[i];
                break;
            }
        }
        serve_converted_or_raw(c, source_rt, rt->target, rt->local_port);
    } else {
        std::string auto_target = target_from_user_agent(request_header(req, "User-Agent"));
        if (!auto_target.empty()) {
            logm("  [AUTO] Port %d UA target=%s\n", rt->local_port, auto_target.c_str());
        }
        serve_converted_or_raw(c, rt, auto_target, rt->local_port);
    }

    shutdown(c, SD_SEND);
    closesocket(c);
}
SOCKET make_listener(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return s;

    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);

    if (bind(s, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR || listen(s, 4) == SOCKET_ERROR) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}
void server_loop(void) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    int active_sockets = 0;
    for (int i = 0; i < g_RouteCount; i++) {
        g_Routes[i].listen_sock = make_listener(g_Routes[i].local_port);
        if (g_Routes[i].listen_sock != INVALID_SOCKET) {
            logm("Listening on 0.0.0.0:%d%s\n",
                 g_Routes[i].local_port,
                 g_Routes[i].is_subconverter ? " (embedded subconverter)" : (g_Routes[i].is_convert ? " (convert)" : " (base)"));
            active_sockets++;
        } else {
            logm("FATAL: cannot bind 0.0.0.0:%d\n", g_Routes[i].local_port);
        }
    }

    if (active_sockets == 0) {
        logm("No valid ports to listen on.\n");
        WSACleanup();
        return;
    }

    for (;;) {
        if (WaitForSingleObject(g_Stop, 0) == WAIT_OBJECT_0) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        SOCKET max_sd = 0;

        for (int i = 0; i < g_RouteCount; i++) {
            SOCKET s = g_Routes[i].listen_sock;
            if (s != INVALID_SOCKET) {
                FD_SET(s, &rfds);
                if (s > max_sd) max_sd = s;
            }
        }

        struct timeval tv = { 1, 0 };
        int r = select((int)max_sd + 1, &rfds, NULL, NULL, &tv);

        if (r > 0) {
            for (int i = 0; i < g_RouteCount; i++) {
                SOCKET s = g_Routes[i].listen_sock;
                if (s != INVALID_SOCKET && FD_ISSET(s, &rfds)) {
                    SOCKET c = accept(s, NULL, NULL);
                    if (c != INVALID_SOCKET) {
                        std::thread([c, i]() {
                            handle_client(c, &g_Routes[i]);
                        }).detach();
                    }
                }
            }
        }
    }

    for (int i = 0; i < g_RouteCount; i++) {
        if (g_Routes[i].listen_sock != INVALID_SOCKET) {
            closesocket(g_Routes[i].listen_sock);
        }
    }
    WSACleanup();
}
