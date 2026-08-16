#pragma once

#ifndef SAFE_CRT_H
#define SAFE_CRT_H

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdint>
#include <cwchar>
#include <cstdlib>

#ifdef _MSC_VER
#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES 1
#endif

namespace safe_crt {

inline int strncpy_s_wrapper(char *dest, size_t destsz, const char *src, size_t count) {
#ifdef _MSC_VER
    return strncpy_s(dest, destsz, src, count);
#else
    if (!dest || destsz == 0) return -1;
    if (count == 0) {
        dest[0] = '\0';
        return 0;
    }
    size_t i = 0;
    for (; i < count && i < destsz - 1 && src && src[i]; ++i) {
        dest[i] = src[i];
    }
    for (; i < destsz; ++i) {
        dest[i] = '\0';
    }
    return 0;
#endif
}

inline int strncat_s_wrapper(char *dest, size_t destsz, const char *src, size_t count) {
#ifdef _MSC_VER
    return strncat_s(dest, destsz, src, count);
#else
    if (!dest || destsz == 0) return -1;
    size_t dest_len = strlen(dest);
    if (dest_len >= destsz) return -1;
    size_t i = 0;
    for (; i < count && dest_len + i < destsz - 1 && src && src[i]; ++i) {
        dest[dest_len + i] = src[i];
    }
    dest[dest_len + i] = '\0';
    return 0;
#endif
}

inline int sscanf_s_wrapper(const char *buffer, const char *format, ...) {
#ifdef _MSC_VER
    va_list args;
    va_start(args, format);
    int result = vsscanf_s(buffer, format, args);
    va_end(args);
    return result;
#else
    va_list args;
    va_start(args, format);
    int result = vsscanf(buffer, format, args);
    va_end(args);
    return result;
#endif
}

inline errno_t fopen_s_wrapper(FILE **pf, const char *filename, const char *mode) {
#ifdef _MSC_VER
    return fopen_s(pf, filename, mode);
#else
    *pf = fopen(filename, mode);
    return *pf ? 0 : errno;
#endif
}

inline char *strtok_s_wrapper(char *str, const char *delim, char **context) {
#ifdef _MSC_VER
    return strtok_s(str, delim, context);
#else
    return strtok_r(str, delim, context);
#endif
}

inline int wcsncpy_s_wrapper(wchar_t *dest, size_t destsz, const wchar_t *src, size_t count) {
#ifdef _MSC_VER
    return wcsncpy_s(dest, destsz, src, count);
#else
    if (!dest || destsz == 0) return -1;
    if (count == 0) {
        dest[0] = L'\0';
        return 0;
    }
    size_t i = 0;
    for (; i < count && i < destsz - 1 && src && src[i]; ++i) {
        dest[i] = src[i];
    }
    for (; i < destsz; ++i) {
        dest[i] = L'\0';
    }
    return 0;
#endif
}

inline int snwprintf_s_wrapper(wchar_t *buffer, size_t count, const wchar_t *format, ...) {
#ifdef _MSC_VER
    va_list args;
    va_start(args, format);
    int result = _vsnwprintf_s(buffer, count, _TRUNCATE, format, args);
    va_end(args);
    return result;
#else
    va_list args;
    va_start(args, format);
    int result = vswprintf(buffer, count, format, args);
    va_end(args);
    return result;
#endif
}

inline int snprintf_s_wrapper(char *buffer, size_t count, const char *format, ...) {
#ifdef _MSC_VER
    va_list args;
    va_start(args, format);
    int result = _vsnprintf_s(buffer, count, _TRUNCATE, format, args);
    va_end(args);
    return result;
#else
    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, count, format, args);
    va_end(args);
    return result;
#endif
}

} // namespace safe_crt

// Macros for easier use
#define SAFE_STRNCPY(dest, src, count) safe_crt::strncpy_s_wrapper(dest, sizeof(dest), src, count)
#define SAFE_STRNCAT(dest, src, count) safe_crt::strncat_s_wrapper(dest, sizeof(dest), src, count)
#define SAFE_SSCANF(buffer, format, ...) safe_crt::sscanf_s_wrapper(buffer, format, __VA_ARGS__)
#define SAFE_FOPEN(pf, filename, mode) safe_crt::fopen_s_wrapper(pf, filename, mode)
#define SAFE_STRTOK(str, delim, context) safe_crt::strtok_s_wrapper(str, delim, context)
#define SAFE_WCSNCPY(dest, src, count) safe_crt::wcsncpy_s_wrapper(dest, sizeof(dest)/sizeof(dest[0]), src, count)
#define SAFE_SNWPRINTF(buffer, format, ...) safe_crt::snwprintf_s_wrapper(buffer, sizeof(buffer)/sizeof(buffer[0]), format, __VA_ARGS__)
#define SAFE_SNPRINTF(buffer, format, ...) safe_crt::snprintf_s_wrapper(buffer, sizeof(buffer), format, __VA_ARGS__)

#endif // SAFE_CRT_H