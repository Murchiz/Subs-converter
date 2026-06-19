#pragma once
#include "types.h"
#include <string>

int fetch_url(const Route *rt, char *buf, int cap, const wchar_t* custom_ua = NULL, int url_index = 0,
              SubMetadata *out_meta = NULL);
void handle_subconverter(SOCKET c, const std::string& req);
void handle_client(SOCKET c, const Route *rt);
SOCKET make_listener(int port);
void server_loop(void);
