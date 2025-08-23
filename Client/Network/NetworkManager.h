#pragma once
#include "../App/AppState.h"
#include <string>
#include <windows.h>

struct HashCheckResponse {
    std::string status;
    std::string message;
};

DWORD WINAPI connect_to_server(LPVOID param);
DWORD WINAPI authenticate_thread(LPVOID param);
void perform_auto_login(AppState* state, HANDLE* auth_thread);
void cleanup_connection(AppState* state);
void send_command(AppState* state, const std::string& command);