#pragma once
#include "../App/AppState.h"
#include <string>
#include <windows.h>

DWORD WINAPI connect_to_server(LPVOID param);
DWORD WINAPI authenticate_thread(LPVOID param);
void cleanup_connection(AppState* state);
void send_command(AppState* state, const std::string& command);