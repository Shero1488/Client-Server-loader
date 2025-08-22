#pragma once
#include <d3d11.h>
#include <windows.h>

extern ID3D11Device* g_pd3dDevice;
extern ID3D11DeviceContext* g_pd3dDeviceContext;
extern IDXGISwapChain* g_pSwapChain;
extern ID3D11RenderTargetView* g_mainRenderTargetView;

bool InitializeDX11(HWND hwnd);
void CleanupRenderTarget();
void CleanupDeviceD3D();
void CreateRenderTarget();