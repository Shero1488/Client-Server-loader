#include "GUI.h"
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <d3d11.h>
#include <iostream>
#include "../Network/NetworkManager.h"

void show_login_page(AppState* state, HANDLE* auth_thread, HANDLE* connect_thread) {
    ImGui::Text("SSL Client - Authentication");
    ImGui::Separator();

    ImGui::Text("Username:");
    ImGui::InputText("##username", state->username, sizeof(state->username));

    ImGui::Text("Password:");
    if (state->show_password)
        ImGui::InputText("##password", state->password, sizeof(state->password));
    else
        ImGui::InputText("##password", state->password, sizeof(state->password), ImGuiInputTextFlags_Password);
    
    ImGui::SameLine();
    ImGui::Checkbox("Show", &state->show_password);

    ImGui::Spacing();

    bool can_authenticate = (state->connection_established == 1 && *auth_thread == NULL);

    if (!can_authenticate)
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.5f);

    if (ImGui::Button("Authenticate", ImVec2(-1, 40)) && can_authenticate) {
        if (strlen(state->username) == 0 || strlen(state->password) == 0) {
            strcpy(state->status, "Please fill all fields!");
            state->auth_result = 3;
        }
        else
            *auth_thread = CreateThread(NULL, 0, authenticate_thread, state, 0, NULL);
    }

    if (!can_authenticate) {
        ImGui::PopStyleVar();
        if (!state->connection_established) {
            ImGui::SameLine();
            ImGui::Text(" (Connecting...)");
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Status: %s", state->status);

    if (state->auth_result == 1) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 255, 0, 255));
        ImGui::Text("✓ Authentication successful");
        ImGui::PopStyleColor();

        static time_t success_time = 0;
        if (success_time == 0)
            success_time = time(NULL);

        if (time(NULL) - success_time >= 2) {
            state->current_page = 1;
            success_time = 0;
        }
    }
    else if (state->auth_result == 2) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255));
        ImGui::Text("✗ Authentication failed");
        ImGui::PopStyleColor();
    }
    else if (state->auth_result == 3) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 100, 100, 255));
        ImGui::Text("⚠ Connection error");
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Text("Connection status: %s",
        state->connection_established ? "Connected" : "Disconnected");
}

void show_dashboard_page(AppState* state, HANDLE* keep_alive_handle) {
    ImGui::Text("Welcome to the system!");
    ImGui::Separator();

    ImGui::Text("Account Information:");
    ImGui::TextWrapped("%s", state->user_info);

    ImGui::Spacing();
    ImGui::Separator();

    ImGui::Text("System Information:");

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    ImGui::Text("Processor: %lu cores", sysInfo.dwNumberOfProcessors);

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    ImGui::Text("Memory: %llu MB total, %llu MB free",
        memInfo.ullTotalPhys / 1024 / 1024,
        memInfo.ullAvailPhys / 1024 / 1024);

    time_t current_time = time(NULL);
    time_t uptime = current_time - state->login_time;
    ImGui::Text("Session time: %lld seconds", (long long)uptime);

    ImGui::Spacing();
    ImGui::Separator();

    ImGui::Text("Server connection: %s",
        state->connection_established ? "Connected" : "Disconnected");

    ImGui::Spacing();
    ImGui::Separator();

    if (strlen(state->server_response) > 0) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Text("Last server response:");
        ImGui::TextWrapped("%s", state->server_response);
    }
}

void move_window(HWND hwnd, ImVec2 window_size, RECT rc) {
    ImGui::SetCursorPos(ImVec2(0, 0));
    if (ImGui::InvisibleButton("Move_detector", ImVec2(window_size.x, window_size.y)));
    if (ImGui::IsItemActive()) {
        GetWindowRect(hwnd, &rc);
        MoveWindow(hwnd, rc.left + ImGui::GetMouseDragDelta().x, rc.top + ImGui::GetMouseDragDelta().y, window_size.x, window_size.y, TRUE);
    }
}

void RenderBlur(HWND hwnd) {
    struct ACCENTPOLICY {
        int na;
        int nf;
        int nc;
        int nA;
    };
    struct WINCOMPATTRDATA {
        int na;
        PVOID pd;
        ULONG ul;
    };

    const HINSTANCE hm = LoadLibrary(L"user32.dll");
    if (hm) {
        typedef BOOL(WINAPI* pSetWindowCompositionAttribute)(HWND, WINCOMPATTRDATA*);
        const pSetWindowCompositionAttribute SetWindowCompositionAttribute = (pSetWindowCompositionAttribute)GetProcAddress(hm, "SetWindowCompositionAttribute");
        if (SetWindowCompositionAttribute) {
            ACCENTPOLICY policy = { 3, 0, 0, 0 };
            WINCOMPATTRDATA data = { 19, &policy, sizeof(ACCENTPOLICY) };
            SetWindowCompositionAttribute(hwnd, &data);
        }
        FreeLibrary(hm);
    }
}