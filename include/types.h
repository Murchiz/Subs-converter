#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <winhttp.h>
#include <string>
#include <vector>

#define SVC_NAME     "SubBridge"
#define SVC_DISPLAY  "Subscription Converter Bridge"
#define UA_WIDE      L"Happ/3.23.0"

#define BODY_CAP     (2048 * 1024)
#define UP_TIMEOUT   15000
#define CL_TIMEOUT   5000

struct DevInfo { char hwid[128]; char os[64]; char ver[64]; char model[256]; };
struct Route { int local_port; int is_convert; int base_port; char target[64]; char urls[8][2048]; int url_count; int use_hwid; int is_subconverter; char user_agents[8][128]; SOCKET listen_sock; };
struct Proxy { char protocol[16]; char name[128]; char server[128]; int port; char uuid[64]; char type[32]; char security[32]; char sni[128]; char fp[64]; char pbk[128]; char sid[64]; char flow[64]; char path[128]; char host[128]; char alterId[16]; char cipher[32]; char alpn[64]; char mode[32]; char extra[1024]; char obfs[32]; char obfs_pass[128]; char up[32]; char down[32]; };

extern Route g_Routes[64];
extern int g_RouteCount;
extern DevInfo g_Dev;
extern SERVICE_STATUS g_Svc;
extern SERVICE_STATUS_HANDLE g_SvcH;
extern HANDLE g_Stop;
extern int g_IsCon;
extern char g_ExeDir[MAX_PATH];

void logm(const char *fmt, ...);
