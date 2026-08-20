#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <climits>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define MAX_PATH PATH_MAX
typedef int SOCKET;
inline constexpr int INVALID_SOCKET = -1;
inline constexpr int SOCKET_ERROR = -1;
typedef unsigned int DWORD;
#endif

#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>

inline constexpr const char* SVC_NAME = "SubBridge";
inline constexpr const char* SVC_DISPLAY = "Subscription Converter Bridge";
inline constexpr const wchar_t* UA_WIDE = L"Happ/3.23.0";

inline constexpr std::size_t BODY_CAP = 2048 * 1024;
inline constexpr uint32_t UP_TIMEOUT = 15000;
inline constexpr uint32_t CL_TIMEOUT = 5000;

struct DevInfo {
    char hwid[128]{};
    char os[64]{};
    char ver[64]{};
    char model[256]{};
};

struct SubMetadata {
    char userinfo[512]{};
    char interval[128]{};
    char disposition[512]{};
    char profile_title[512]{};
    char announce[2048]{};
    char profile_web_page_url[1024]{};
    char support_url[512]{};
    char refill_date[128]{};
    char content_type[128]{};
};

struct Route {
    int local_port{0};
    int is_convert{0};
    int base_port{0};
    char target[64]{};
    char name[128]{};
    char urls[8][2048]{};
    int url_count{0};
    int use_hwid{0};
    int is_subconverter{0};
    char user_agents[8][128]{};
    SOCKET listen_sock{INVALID_SOCKET};
};

struct Rule {
    char outbound[64]{};
    std::vector<std::string> domains{};
    std::vector<std::string> ips{};
    std::vector<std::string> protocols{};
    std::string port{};
    std::string network{};
};

struct Proxy {
    char protocol[16]{};
    char name[128]{};
    char server[128]{};
    int port{0};
    char uuid[64]{};
    char type[32]{};
    char security[32]{};
    char sni[128]{};
    char fp[64]{};
    char pbk[128]{};
    char sid[64]{};
    char flow[64]{};
    char path[128]{};
    char host[128]{};
    char alterId[16]{};
    char cipher[32]{};
    char alpn[64]{};
    char mode[32]{};
    char extra[4096]{};
    char obfs[32]{};
    char obfs_pass[128]{};
    char up[32]{};
    char down[32]{};
};

extern Route g_Routes[64];
extern int g_RouteCount;
extern DevInfo g_Dev;
#ifdef _WIN32
extern SERVICE_STATUS g_Svc;
extern SERVICE_STATUS_HANDLE g_SvcH;
extern HANDLE g_Stop;
#else
extern volatile sig_atomic_t g_Stop;
#endif
extern int g_IsCon;
extern char g_ExeDir[MAX_PATH];

void logm(const char *fmt, ...);

template <typename... Args>
inline void logm_fmt(std::format_string<Args...> fmt, Args&&... args) {
    if (!g_IsCon) return;
    std::string s = std::format(fmt, std::forward<Args>(args)...);
    logm("%s", s.c_str());
}


