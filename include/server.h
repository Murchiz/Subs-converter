#pragma once
#include "types.h"
#include <string>
#include <string_view>

void copy_limited(char *dst, int cap, const char *src);

int fetch_url(const Route *rt, char *buf, int cap, const wchar_t* custom_ua = nullptr, int url_index = 0,
              SubMetadata *out_meta = nullptr);
void handle_subconverter(SOCKET c, std::string_view req);
void handle_client(SOCKET c, const Route *rt);
SOCKET make_listener(int port);
void server_loop();
