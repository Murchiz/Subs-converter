#include "server.h"
#include "utils.h"
#include "parser.h"
#include "generator.h"
#include <thread>
#include <stdio.h>
int fetch_url(const Route *rt, char *buf, int cap, const wchar_t* custom_ua, int url_index,
              char *out_userinfo, int userinfo_cap,
              char *out_interval, int interval_cap,
              char *out_disposition, int disposition_cap) {
    HINTERNET hS = NULL, hC = NULL, hR = NULL;
    int total = -1;
    char full_url[4096];

    if (rt->is_convert) {
        snprintf(full_url, sizeof(full_url),
                 "http://127.0.0.1:25500/sub?target=%s&url=http%%3A%%2F%%2F127.0.0.1%%3A%d",
                 rt->target, rt->base_port);
    } else {
        strcpy(full_url, rt->urls[url_index]);
    }

    wchar_t wurl[4096];
    MultiByteToWideChar(CP_UTF8, 0, full_url, -1, wurl, 4096);

    URL_COMPONENTS uc;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.dwHostNameLength = -1;
    uc.dwUrlPathLength = -1;

    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        return -1;
    }

    wchar_t host[256] = { 0 };
    wcsncpy(host, uc.lpszHostName, uc.dwHostNameLength);

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

    hR = WinHttpOpenRequest(hC, L"GET", uc.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                            (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
    if (!hR) goto out;

    if (rt->use_hwid) {
        wchar_t hdr[1024], wH[128], wO[64], wV[64], wM[256];
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.hwid, -1, wH, 128);
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.os, -1, wO, 64);
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.ver, -1, wV, 64);
        MultiByteToWideChar(CP_UTF8, 0, g_Dev.model, -1, wM, 256);
        _snwprintf(hdr, sizeof(hdr) / sizeof(hdr[0]),
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

    if (out_userinfo && userinfo_cap > 0) {
        out_userinfo[0] = '\0';
        wchar_t wbuf[512] = {0};
        DWORD wlen = sizeof(wbuf);
        if (WinHttpQueryHeaders(hR, WINHTTP_QUERY_CUSTOM, L"subscription-userinfo", wbuf, &wlen, WINHTTP_NO_HEADER_INDEX)) {
            WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out_userinfo, userinfo_cap, NULL, NULL);
        }
    }
    if (out_interval && interval_cap > 0) {
        out_interval[0] = '\0';
        wchar_t wbuf[128] = {0};
        DWORD wlen = sizeof(wbuf);
        if (WinHttpQueryHeaders(hR, WINHTTP_QUERY_CUSTOM, L"profile-update-interval", wbuf, &wlen, WINHTTP_NO_HEADER_INDEX)) {
            WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out_interval, interval_cap, NULL, NULL);
        }
    }
    if (out_disposition && disposition_cap > 0) {
        out_disposition[0] = '\0';
        wchar_t wbuf[512] = {0};
        DWORD wlen = sizeof(wbuf);
        if (WinHttpQueryHeaders(hR, WINHTTP_QUERY_CUSTOM, L"content-disposition", wbuf, &wlen, WINHTTP_NO_HEADER_INDEX)) {
            WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out_disposition, disposition_cap, NULL, NULL);
        }
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
void handle_subconverter(SOCKET c, const std::string& req) {
    size_t q_pos = req.find('?');
    size_t space_pos = req.find(' ', q_pos);
    if (q_pos == std::string::npos || space_pos == std::string::npos) {
        const char *r = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
        send(c, r, strlen(r), 0);
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
        send(c, r, strlen(r), 0);
        return;
    }

    Route temp_rt = { 0 };
    int internal_port = 0;
    if (url.find("http://127.0.0.1:") == 0) {
        internal_port = atoi(url.c_str() + 17);
    }
    
    bool matched_route = false;
    if (internal_port > 0) {
        for (int i = 0; i < g_RouteCount; i++) {
            if (g_Routes[i].local_port == internal_port) {
                temp_rt.url_count = g_Routes[i].url_count;
                for (int j = 0; j < temp_rt.url_count; j++) {
                    strcpy(temp_rt.urls[j], g_Routes[i].urls[j]);
                    if (target != "clash" && (_stricmp(g_Routes[i].user_agents[j], "ClashMeta") == 0 || _stricmp(g_Routes[i].user_agents[j], "Happ") == 0)) {
                        strcpy(temp_rt.user_agents[j], "Happ/3.23.0");
                    } else {
                        strcpy(temp_rt.user_agents[j], g_Routes[i].user_agents[j]);
                    }
                }
                temp_rt.use_hwid = g_Routes[i].use_hwid;
                matched_route = true;
                break;
            }
        }
    } else {
        // Try matching raw URL to inherit configured User-Agent
        for (int i = 0; i < g_RouteCount; i++) {
            for (int j = 0; j < g_Routes[i].url_count; j++) {
                if (url == g_Routes[i].urls[j]) {
                    temp_rt.url_count = 1;
                    strcpy(temp_rt.urls[0], g_Routes[i].urls[j]);
                    if (target != "clash" && (_stricmp(g_Routes[i].user_agents[j], "ClashMeta") == 0 || _stricmp(g_Routes[i].user_agents[j], "Happ") == 0)) {
                        strcpy(temp_rt.user_agents[0], "Happ/3.23.0");
                    } else {
                        strcpy(temp_rt.user_agents[0], g_Routes[i].user_agents[j]);
                    }
                    temp_rt.use_hwid = g_Routes[i].use_hwid;
                    matched_route = true;
                    break;
                }
            }
            if (matched_route) break;
        }
    }
    
    if (temp_rt.url_count == 0) {
        strcpy(temp_rt.urls[0], url.c_str());
        temp_rt.url_count = 1;
    }
    temp_rt.use_hwid = 0;

    char *body = (char *)HeapAlloc(GetProcessHeap(), 0, BODY_CAP);
    
    std::string out_payload;
    std::string raw_clash_proxies;
    std::string raw_clash_names;
    std::vector<Proxy> all_proxies;
    int success_count = 0;
    
    char userinfo[512] = {0};
    char interval[128] = {0};
    char disposition[512] = {0};
    
    for (int i = 0; i < temp_rt.url_count; i++) {
        char temp_userinfo[512] = {0};
        char temp_interval[128] = {0};
        char temp_disp[512] = {0};
        int blen = fetch_url(&temp_rt, body, BODY_CAP, NULL, i,
                             temp_userinfo, sizeof(temp_userinfo),
                             temp_interval, sizeof(temp_interval),
                             temp_disp, sizeof(temp_disp));
        if (blen >= 0) {
            success_count++;
            if (userinfo[0] == '\0' && temp_userinfo[0] != '\0') {
                strcpy(userinfo, temp_userinfo);
            }
            if (interval[0] == '\0' && temp_interval[0] != '\0') {
                strcpy(interval, temp_interval);
            }
            if (disposition[0] == '\0' && temp_disp[0] != '\0') {
                strcpy(disposition, temp_disp);
            }
            std::string payload(body, blen);
            if (target == "clash" && payload.find("proxies:") != std::string::npos) {
                // Extract Native Clash YAML proxies
                size_t p_start = payload.find("proxies:");
                if (p_start != std::string::npos) {
                    p_start += 8; // skip 'proxies:'
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
            } else {
                std::string decoded;
                size_t first_char = payload.find_first_not_of(" \t\r\n");
                if (first_char != std::string::npos && (payload[first_char] == '[' || payload[first_char] == '{')) {
                    decoded = payload;
                } else {
                    decoded = (payload.find("://") != std::string::npos) ? payload : base64_decode(payload);
                }
                auto p = parse_proxies(decoded);
                all_proxies.insert(all_proxies.end(), p.begin(), p.end());
            }
        }
    }

    if (success_count > 0) {
        if (target == "clash") {
            out_payload = gen_clash(all_proxies);
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
        } else if (target == "singbox" || target == "sing-box") {
            out_payload = gen_singbox(all_proxies);
        } else {
            out_payload = gen_v2ray(all_proxies);
        }

        std::string extra_hdrs;
        if (userinfo[0]) extra_hdrs += "subscription-userinfo: " + std::string(userinfo) + "\r\n";
        if (interval[0]) extra_hdrs += "profile-update-interval: " + std::string(interval) + "\r\n";
        if (disposition[0]) extra_hdrs += "content-disposition: " + std::string(disposition) + "\r\n";

        std::string hdr = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/plain; charset=utf-8\r\n"
                          "Content-Length: " + std::to_string(out_payload.length()) + "\r\n"
                          + extra_hdrs +
                          "Connection: close\r\n\r\n";
        send(c, hdr.c_str(), (int)hdr.length(), 0);
        send(c, out_payload.c_str(), (int)out_payload.length(), 0);
        logm("  [SUBCONV] target=%s -> 200 OK (%zu bytes)\n", target.c_str(), out_payload.length());
    } else {
        std::string e = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
        send(c, e.c_str(), e.length(), 0);
        logm("  [SUBCONV] target=%s -> 502 Fail\n", target.c_str());
    }
    HeapFree(GetProcessHeap(), 0, body);
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

    char *body = (char *)HeapAlloc(GetProcessHeap(), 0, BODY_CAP);
    if (!body) {
        const char *e = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOOM";
        send(c, e, (int)strlen(e), 0);
        closesocket(c);
        return;
    }

    std::string final_payload;
    int success_count = 0;
    
    char userinfo[512] = {0};
    char interval[128] = {0};
    char disposition[512] = {0};

    for (int i = 0; i < rt->url_count; i++) {
        char temp_userinfo[512] = {0};
        char temp_interval[128] = {0};
        char temp_disp[512] = {0};
        int blen = fetch_url(rt, body, BODY_CAP, NULL, i,
                             temp_userinfo, sizeof(temp_userinfo),
                             temp_interval, sizeof(temp_interval),
                             temp_disp, sizeof(temp_disp));
        if (blen > 0) {
            success_count++;
            if (userinfo[0] == '\0' && temp_userinfo[0] != '\0') {
                strcpy(userinfo, temp_userinfo);
            }
            if (interval[0] == '\0' && temp_interval[0] != '\0') {
                strcpy(interval, temp_interval);
            }
            if (disposition[0] == '\0' && temp_disp[0] != '\0') {
                strcpy(disposition, temp_disp);
            }
            if (!final_payload.empty()) final_payload += "\n";
            final_payload.append(body, blen);
        }
    }

    std::string extra_hdrs;
    if (userinfo[0]) extra_hdrs += "subscription-userinfo: " + std::string(userinfo) + "\r\n";
    if (interval[0]) extra_hdrs += "profile-update-interval: " + std::string(interval) + "\r\n";
    if (disposition[0]) extra_hdrs += "content-disposition: " + std::string(disposition) + "\r\n";

    if (success_count > 0) {
        std::string hdr = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/plain; charset=utf-8\r\n"
                          "Content-Length: " + std::to_string(final_payload.length()) + "\r\n"
                          + extra_hdrs +
                          "Connection: close\r\n\r\n";
        send(c, hdr.c_str(), (int)hdr.length(), 0);
        send(c, final_payload.c_str(), (int)final_payload.length(), 0);
        logm("  [OK] 200  %zu bytes\n\n", final_payload.length());
    } else {
        int el = snprintf(body, BODY_CAP, "upstream error");
        char err_hdr[256];
        int hl = snprintf(err_hdr, sizeof(err_hdr),
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n", el);
        send(c, err_hdr, hl, 0);
        send(c, body, el, 0);
        logm("  [FAIL] 502  upstream failed\n\n");
    }

    HeapFree(GetProcessHeap(), 0, body);
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
