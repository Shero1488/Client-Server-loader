#pragma once
#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <chrono>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

void get_hwid(char* hwid, size_t size);
void generate_md5_hash(const char* input, char* output);
void get_cpuid_hash(char* hash_output);

struct DecodedToken {
    std::string status;
    std::string message;
    std::string token;
    long long timestamp;
    std::string cpuid;
    std::string ip;
};

bool parse_json_response(const char* json_str, DecodedToken& decoded);
bool verify_token(const DecodedToken& decoded, const char* client_ip,
    const char* credentials, const char* local_cpuid_hash);

class AntiDebugSystem {
private:
    static const int XOR_KEY = 0x55AA33CC;

    static const char* encryptedTools[8];
    static const char* encryptedError;

    static std::string DecryptString(const char* encrypted, int key) {
        std::string result = encrypted;
        for (char& c : result) {
            c ^= key;
        }
        return result;
    }

    static bool CheckDebuggerAPI() {
        return IsDebuggerPresent() != FALSE;
    }

    static bool CheckDebuggerPEB() {
#ifdef _WIN64
        ULONG_PTR pebAddress = __readgsqword(0x60);
#else
        ULONG_PTR pebAddress = __readfsdword(0x30);
#endif

        BYTE beingDebugged = *((BYTE*)(pebAddress + 2));
        return beingDebugged != 0;
    }

    static bool CheckNtGlobalFlag() {
#ifdef _WIN64
        ULONG_PTR pebAddress = __readgsqword(0x60);
        DWORD ntGlobalFlag = *((DWORD*)(pebAddress + 0xBC));
#else
        ULONG_PTR pebAddress = __readfsdword(0x30);
        DWORD ntGlobalFlag = *((DWORD*)(pebAddress + 0x68));
#endif
        return (ntGlobalFlag & 0x70) != 0;
    }

    static bool CheckBreakpoints() {
        BYTE* code = (BYTE*)&CheckBreakpoints;
        if (code[0] == 0xCC) return true;

        return false;
    }

    static bool CheckTiming() {
        auto start = std::chrono::high_resolution_clock::now();

        volatile int dummy = 0;
        for (int i = 0; i < 1000000; i++) {
            dummy += i * i;
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        return duration.count() > 50000;
    }

    //static bool CheckDebugTools() {
    //    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    //    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    //    PROCESSENTRY32 pe;
    //    pe.dwSize = sizeof(PROCESSENTRY32);

    //    bool found = false;

    //    if (Process32First(hSnapshot, &pe)) {
    //        do {
    //            for (int i = 0; i < 8; i++) {
    //                std::string toolName = DecryptString(encryptedTools[i], XOR_KEY);

    //                std::string processName = pe.szExeFile;
    //                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
    //                std::transform(toolName.begin(), toolName.end(), toolName.begin(), ::tolower);

    //                if (processName.find(toolName) != std::string::npos) {
    //                    found = true;
    //                    break;
    //                }
    //            }
    //            if (found) break;
    //        } while (Process32Next(hSnapshot, &pe));
    //    }

    //    CloseHandle(hSnapshot);
    //    return found;
    //}

    //static bool CheckParentProcess() {
    //    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    //    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    //    PROCESSENTRY32 pe;
    //    pe.dwSize = sizeof(PROCESSENTRY32);

    //    DWORD currentPid = GetCurrentProcessId();
    //    DWORD parentPid = 0;

    //    if (Process32First(hSnapshot, &pe)) {
    //        do {
    //            if (pe.th32ProcessID == currentPid) {
    //                parentPid = pe.th32ParentProcessID;
    //                break;
    //            }
    //        } while (Process32Next(hSnapshot, &pe));
    //    }

    //    CloseHandle(hSnapshot);

    //    if (parentPid != 0 && parentPid != currentPid) {
    //        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    //        if (hSnapshot != INVALID_HANDLE_VALUE) {
    //            if (Process32First(hSnapshot, &pe)) {
    //                do {
    //                    if (pe.th32ProcessID == parentPid) {
    //                        std::string parentName = pe.szExeFile;
    //                        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);

    //                        if (parentName.find("debug") != std::string::npos ||
    //                            parentName.find("dbg") != std::string::npos ||
    //                            parentName.find("ida") != std::string::npos ||
    //                            parentName.find("x64dbg") != std::string::npos ||
    //                            parentName.find("olly") != std::string::npos) {
    //                            CloseHandle(hSnapshot);
    //                            return true;
    //                        }
    //                        break;
    //                    }
    //                } while (Process32Next(hSnapshot, &pe));
    //            }
    //            CloseHandle(hSnapshot);
    //        }
    //    }

    //    return false;
    //}

    static void SelfDestruct() {
        for (int i = 0; i < 5; i++) {
            __try {
                int* ptr = nullptr;
                *ptr = 0xDEADBEEF;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
    }

public:
    static bool PerformComprehensiveCheck() {
        if (CheckDebuggerAPI() || CheckDebuggerPEB() || CheckNtGlobalFlag())
            return true;

        if (CheckBreakpoints())
            return true;

        if (CheckTiming())
            return true;

        /*if (CheckDebugTools())
            return true;

        if (CheckParentProcess())
            return true;*/

        return false;
    }

    static void InitializeProtection() {
        encryptedTools[0] = "\x2A\x2B\x2C\x2C\x31\x2E\x2A\x2B"; // ollydbg
        encryptedTools[1] = "\x37\x3B\x3B\x2E\x2A\x2B"; // x64dbg
        encryptedTools[2] = "\x2C\x2E\x2A\x33\x37"; // idaq
        encryptedTools[3] = "\x2C\x2E\x2A\x33\x37\x3B\x3B"; // idaq64
        encryptedTools[4] = "\x36\x2C\x2D\x2E\x2A\x2B"; // windbg
        encryptedTools[5] = "\x32\x2B\x2C\x33\x35\x2C\x36\x2C\x2D\x2E\x2A\x2B"; // procmon
        encryptedTools[6] = "\x32\x2B\x2C\x33\x35\x2A\x2F\x2C\x36"; // procexp
        encryptedTools[7] = "\x2A\x2D\x2C\x2A\x35\x2C\x2D\x2E\x2A\x2D\x2C\x2A\x2D\x2C"; // cheatengine

        encryptedError = "\x2D\x2C\x2A\x2C\x2D\x21\x2A\x2D\x2C\x2A\x2D\x2C\x24\x2D\x2C\x2A\x2D\x2C"; // Debugger detected

        if (PerformComprehensiveCheck()) {
            std::string errorMsg = DecryptString(encryptedError, XOR_KEY);
            MessageBoxA(nullptr, errorMsg.c_str(), "Security Error", MB_ICONERROR);
            SelfDestruct();
        }

        HANDLE hThread = CreateThread(nullptr, 0, MonitoringThread, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }

    static DWORD WINAPI MonitoringThread(LPVOID) {
        while (true) {
            if (PerformComprehensiveCheck())
                SelfDestruct();
            
            Sleep(2000);
        }
        return 0;
    }

    static void QuickCheck() {
        if (CheckDebuggerAPI() || CheckDebuggerPEB())
            SelfDestruct(); 
    }
};

class Hasher {
public:
    static std::string calculateHash(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + filename);
        }

        uint32_t hash = 0;
        char buffer[1024];

        while (file.read(buffer, sizeof(buffer))) {
            for (size_t i = 0; i < file.gcount(); ++i) {
                hash = (hash << 5) + hash + buffer[i];
            }
        }

        std::stringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << hash;
        return ss.str();
    }
};