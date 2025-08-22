#include "SecurityUtils.h"
#include <iphlpapi.h>
#include <intrin.h>
#include <nlohmann/json.hpp>
#include <iostream>

#define TOKEN_SIZE 33

using json = nlohmann::json;

void get_hwid(char* hwid, size_t size) {
    HKEY hKey;
    DWORD type, size_data = size;
    char buffer[256] = { 0 };

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "MachineGuid", NULL, &type, (LPBYTE)buffer, &size_data) == ERROR_SUCCESS) {
            strncpy(hwid, buffer, size - 1);
            RegCloseKey(hKey);
            return;
        }
        RegCloseKey(hKey);
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);

    DWORD volumeSerialNumber = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volumeSerialNumber, NULL, NULL, NULL, 0);

    PIP_ADAPTER_INFO adapterInfo = NULL;
    ULONG adapterInfoSize = 0;
    GetAdaptersInfo(adapterInfo, &adapterInfoSize);
    adapterInfo = (IP_ADAPTER_INFO*)malloc(adapterInfoSize);
    if (adapterInfo && GetAdaptersInfo(adapterInfo, &adapterInfoSize) == ERROR_SUCCESS) {
        snprintf(hwid, size, "%lu-%lu-%lu-%02X%02X%02X%02X%02X%02X-%lu",
            sysInfo.dwProcessorType,
            memInfo.ullTotalPhys / 1024 / 1024,
            volumeSerialNumber,
            adapterInfo->Address[0], adapterInfo->Address[1], adapterInfo->Address[2],
            adapterInfo->Address[3], adapterInfo->Address[4], adapterInfo->Address[5],
            GetTickCount());
        free(adapterInfo);
    }
    else {
        snprintf(hwid, size, "%lu-%lu-%lu-%lu",
            sysInfo.dwProcessorType,
            memInfo.ullTotalPhys / 1024 / 1024,
            volumeSerialNumber,
            GetTickCount());
    }
}

void generate_md5_hash(const char* input, char* output) {
    unsigned int hash[4] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };

    for (size_t i = 0; input[i] != '\0'; i++) {
        hash[i % 4] = (hash[i % 4] << 5) | (hash[i % 4] >> 27);
        hash[i % 4] ^= input[i];
        hash[i % 4] += 0x9E3779B9;
    }

    for (int i = 0; i < 4; i++)
        sprintf(output + (i * 8), "%08x", hash[i]);
    
    output[32] = '\0';
}

void get_cpuid_hash(char* hash_output) {
    int cpuinfo[4];
    __cpuid(cpuinfo, 1);

    char cpuid_str[128];
    snprintf(cpuid_str, sizeof(cpuid_str), "%08X%08X%08X%08X",
        cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);

    DWORD volumeSerialNumber = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volumeSerialNumber, NULL, NULL, NULL, 0);

    char full_input[256];
    snprintf(full_input, sizeof(full_input), "%s%lu%lu",
        cpuid_str, memInfo.ullTotalPhys, volumeSerialNumber);

    generate_md5_hash(full_input, hash_output);
}

bool parse_json_response(const char* json_str, DecodedToken& decoded) {
    try {
        json j = json::parse(json_str);

        decoded.status = j.value("status", "");
        decoded.token = j.value("token", "");
        decoded.timestamp = j.value("timestamp", 0LL);
        decoded.hash_cpuid = j.value("hash_cpuid", "");
        decoded.message = j.value("message", "");
        decoded.client_ip = j.value("client_ip", "");

        return !decoded.status.empty();
    }
    catch (const json::parse_error& e) {
        printf("JSON parse error: %s\n", e.what());
        return false;
    }
}

bool verify_token(const DecodedToken& decoded, const char* client_ip,
    const char* credentials, const char* local_cpuid_hash) {
    if (decoded.status != "success")
        return false;

    if (decoded.hash_cpuid != local_cpuid_hash)
        return false;

    time_t now = time(0);

    if (llabs(now - decoded.timestamp) > 15)
        return false;

    char expected_token[TOKEN_SIZE];
    char hash_input[1024];
    snprintf(hash_input, sizeof(hash_input), "%s%s%s%ld",
        client_ip, credentials, local_cpuid_hash, decoded.timestamp);
    generate_md5_hash(hash_input, expected_token);

    return decoded.token == expected_token;
}