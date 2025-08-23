#include "GUI.h"
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <d3d11.h>
#include <iostream>
#include "../Network/NetworkManager.h"
#include <fstream>
#include <string>
#include <filesystem>
#include "../Utils/CredentialsManager.h"
namespace fs = std::filesystem;

void show_login_page(AppState* state, HANDLE* auth_thread, HANDLE* connect_thread) {
    ImGui::Text(xorstr_("SSL Client - Authentication"));
    ImGui::Separator();

    ImGui::Text(xorstr_("Username:"));
    ImGui::InputText(xorstr_("##username"), state->username, sizeof(state->username));

    ImGui::Text(xorstr_("Password:"));
    if (state->show_password)
        ImGui::InputText(xorstr_("##password"), state->password, sizeof(state->password));
    else
        ImGui::InputText(xorstr_("##password"), state->password, sizeof(state->password), ImGuiInputTextFlags_Password);
    
    ImGui::SameLine();
    ImGui::Checkbox(xorstr_("Show"), &state->show_password);

    ImGui::Spacing();

    bool can_authenticate = (state->connection_established == 1 && *auth_thread == NULL);

    if (!can_authenticate)
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.5f);

    if (ImGui::Button(xorstr_("Authenticate"), ImVec2(-1, 40)) && can_authenticate) {
        if (strlen(state->username) == 0 || strlen(state->password) == 0) {
            strcpy(state->status, xorstr_("Please fill all fields!"));
            state->auth_result = 3;
        }
        else {
            *auth_thread = CreateThread(NULL, 0, authenticate_thread, state, 0, NULL);
            CredentialsManager::SaveCredentials(state);
        }   
    }

    if (!can_authenticate) {
        ImGui::PopStyleVar();
        if (!state->connection_established) {
            ImGui::SameLine();
            ImGui::Text(xorstr_(" (Connecting...)"));
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text(xorstr_("Status: %s"), state->status);

    if (state->auth_result == 1) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 255, 0, 255));
        ImGui::Text(xorstr_("✓ Authentication successful"));
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
        ImGui::Text(xorstr_("✗ Authentication failed"));
        ImGui::PopStyleColor();
    }
    else if (state->auth_result == 3) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 100, 100, 255));
        ImGui::Text(xorstr_("⚠ Connection error"));
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Text(xorstr_("Connection status: %s"),
        state->connection_established ? xorstr_("Connected") : xorstr_("Disconnected"));

    if (ImGui::Button(xorstr_("Settings")))
        state->current_page = 2;
}

void show_dashboard_page(AppState* state, HANDLE* keep_alive_handle) {
    ImGui::Text(xorstr_("Welcome to the system!"));
    ImGui::Separator();

    ImGui::Text(xorstr_("Account Information:"));
    ImGui::TextWrapped(xorstr_("%s"), state->user_info);

    ImGui::Spacing();
    ImGui::Separator();

    ImGui::Text(xorstr_("System Information:"));

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    ImGui::Text(xorstr_("Processor: %lu cores"), sysInfo.dwNumberOfProcessors);

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    ImGui::Text(xorstr_("Memory: %llu MB total, %llu MB free"),
        memInfo.ullTotalPhys / 1024 / 1024,
        memInfo.ullAvailPhys / 1024 / 1024);

    time_t current_time = time(NULL);
    time_t uptime = current_time - state->login_time;
    ImGui::Text(xorstr_("Session time: %lld seconds"), (long long)uptime);

    ImGui::Spacing();
    ImGui::Separator();

    ImGui::Text(xorstr_("Server connection: %s"),
        state->connection_established ? xorstr_("Connected") : xorstr_("Disconnected"));

    ImGui::Spacing();
    ImGui::Separator();

    if (strlen(state->server_response) > 0) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Text(xorstr_("Last server response:"));
        ImGui::TextWrapped(xorstr_("%s"), state->server_response);
    }

    if (ImGui::Button(xorstr_("Settings##2")))
        state->current_page = 3;
}

void show_settings_page(AppState* state) {
    if (ImGui::Button(xorstr_("Back")))
        state->current_page = 0;

    static bool prev_auto_login = state->auto_login;
    static bool prev_save_creds = state->save_creds;

    ImGui::Checkbox(xorstr_("Auto-login"), &state->auto_login);
    ImGui::Checkbox(xorstr_("Save credentials"), &state->save_creds);

    if (state->auto_login != prev_auto_login || state->save_creds != prev_save_creds) {
        CredentialsManager::SaveCredentials(state);
        prev_auto_login = state->auto_login;
        prev_save_creds = state->save_creds;
    }
}

void show_settings_page2(AppState* state) {
    if (ImGui::Button(xorstr_("Back")))
        state->current_page = 1;

    static bool prev_auto_login = state->auto_login;
    static bool prev_save_creds = state->save_creds;

    ImGui::Checkbox(xorstr_("Auto-login"), &state->auto_login);
    ImGui::Checkbox(xorstr_("Save credentials"), &state->save_creds);

    if (state->auto_login != prev_auto_login || state->save_creds != prev_save_creds) {
        CredentialsManager::SaveCredentials(state);
        prev_auto_login = state->auto_login;
        prev_save_creds = state->save_creds;
    }
}

void move_window(HWND hwnd, ImVec2 window_size, RECT rc) {
    ImGui::SetCursorPos(ImVec2(0, 0));
    if (ImGui::InvisibleButton(xorstr_("Move_detector"), ImVec2(window_size.x, window_size.y)));
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

    const HINSTANCE hm = LoadLibrary(xorstr_(L"user32.dll"));
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