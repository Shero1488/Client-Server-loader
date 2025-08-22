#pragma once
#include <windows.h>
#include <string>

void get_hwid(char* hwid, size_t size);
void generate_md5_hash(const char* input, char* output);
void get_cpuid_hash(char* hash_output);

struct DecodedToken {
    std::string status;
    std::string token;
    long long timestamp;
    std::string hash_cpuid;
    std::string message;
    std::string client_ip;
};

bool parse_json_response(const char* json_str, DecodedToken& decoded);
bool verify_token(const DecodedToken& decoded, const char* client_ip,
    const char* credentials, const char* local_cpuid_hash);