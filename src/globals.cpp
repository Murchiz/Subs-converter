#include "types.h"
#include <cstdio>
#include <cstdarg>

Route g_Routes[64]{};
int g_RouteCount = 0;
DevInfo g_Dev{};
SERVICE_STATUS g_Svc{};
SERVICE_STATUS_HANDLE g_SvcH{nullptr};
HANDLE g_Stop = nullptr;
int g_IsCon = 0;
char g_ExeDir[MAX_PATH]{};

void logm(const char *fmt, ...) {
    if (!g_IsCon) return;
    va_list ap;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::fflush(stdout);
}
