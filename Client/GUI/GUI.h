#pragma once
#include "../App/AppState.h"
#include <windows.h>
#include <imgui.h>

void show_login_page(AppState* state, HANDLE* auth_thread, HANDLE* connect_thread);
void show_dashboard_page(AppState* state, HANDLE* keep_alive_handle);
void move_window(HWND hwnd, ImVec2 window_size, RECT rc);
void RenderBlur(HWND hwnd);