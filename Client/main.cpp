#include "App/AppState.h"
#include "Network/NetworkManager.h"
#include "GUI/GUI.h"
#include "GUI/DX11Renderer.h"
#include "Security/SecurityUtils.h"
#include <windows.h>
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include "Utils/CredentialsManager.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

const char* AntiDebugSystem::encryptedTools[8] = { 0 };
const char* AntiDebugSystem::encryptedError = nullptr;

#define SECURITY_CHECK() AntiDebugSystem::QuickCheck()
#define INIT_SECURITY() AntiDebugSystem::InitializeProtection()

void die(const char* msg) {
    fprintf(stderr, xorstr_("%s\n"), msg);
    MessageBoxA(NULL, msg, xorstr_("Error"), MB_ICONERROR);
    exit(EXIT_FAILURE);
}

ImVec2 screen_res{ 0, 0 };
ImVec2 window_pos{ 0, 0 };
ImVec2 window_size{ 500, 500 };
HWND hwnd;
RECT rc;

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
#ifdef _DEBUG
    AllocConsole();
    freopen_s(reinterpret_cast<FILE**>(stdin), xorstr_("CONIN$"), xorstr_("r"), stdin);
    freopen_s(reinterpret_cast<FILE**>(stdout), xorstr_("CONOUT$"), xorstr_("w"), stdout);
#endif

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    std::string filename = path;
    std::cout << xorstr_("Hash: ") << Hasher::calculateHash(filename) << std::endl;

    //INIT_SECURITY();

    AppState state = { 0 };
    state.auth_result = 0;
    state.connected = 0;
    state.show_password = 0;
    state.registered = 0;
    state.current_page = 0;
    state.sockfd = INVALID_SOCKET;
    state.ssl = NULL;
    state.ctx = NULL;
    state.connection_established = 0;
    state.auto_login = false;
    state.save_creds = false;
    get_hwid(state.hwid, sizeof(state.hwid));

    CredentialsManager::LoadCredentials(&state);

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, xorstr_(L"SSL Client"), NULL };
    RegisterClassExW(&wc);
    hwnd = CreateWindowExW(NULL, wc.lpszClassName, xorstr_(L"SSL Client"), WS_POPUP,
        (GetSystemMetrics(SM_CXSCREEN) / 2) - (window_size.x / 2),
        (GetSystemMetrics(SM_CYSCREEN) / 2) - (window_size.y / 2),
        window_size.x, window_size.y, 0, 0, 0, 0);
    RenderBlur(hwnd);
    SetWindowLongA(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 255, LWA_ALPHA);

    if (!InitializeDX11(hwnd)) {
        die(xorstr_("DirectX 11 initialization error"));
    }

    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    HANDLE auth_thread = NULL;
    HANDLE connect_thread = NULL;
    HANDLE keep_alive_thread_handle = NULL;

    connect_thread = CreateThread(NULL, 0, connect_to_server, &state, 0, NULL);

    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(window_size.x, window_size.y));
        ImGui::SetNextWindowBgAlpha(1.0f);

        if (state.current_page == 0)
            perform_auto_login(&state, &auth_thread);

        if (state.current_page == 0) {
            ImGui::Begin(xorstr_("SSL Client - Login"), NULL,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
            show_login_page(&state, &auth_thread, &connect_thread);
        }
        else if (state.current_page == 1) {
            ImGui::Begin(xorstr_("SSL Client - Dashboard"), NULL,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
            show_dashboard_page(&state, &keep_alive_thread_handle);
        }
        else if (state.current_page == 2) {
            ImGui::Begin(xorstr_("SSL Client - Settings"), NULL,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
            show_settings_page(&state);
        }
        else {
            ImGui::Begin(xorstr_("SSL Client - Settings"), NULL,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
            show_settings_page2(&state);
        }

        move_window(hwnd, window_size, rc);
        RenderBlur(hwnd);
        ImGui::End();

        ImGui::Render();
        const float clear_color_with_alpha[4] = { 0.45f, 0.55f, 0.60f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);

        if (connect_thread != NULL && WaitForSingleObject(connect_thread, 0) == WAIT_OBJECT_0) {
            CloseHandle(connect_thread);
            connect_thread = NULL;
        }

        if (auth_thread != NULL && WaitForSingleObject(auth_thread, 0) == WAIT_OBJECT_0) {
            CloseHandle(auth_thread);
            auth_thread = NULL;
        }
    }

    cleanup_connection(&state);
    if (keep_alive_thread_handle != NULL) {
        TerminateThread(keep_alive_thread_handle, 0);
        CloseHandle(keep_alive_thread_handle);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}