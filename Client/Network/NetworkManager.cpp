#include "NetworkManager.h"
#include "../Security/SecurityUtils.h"
#include <winsock2.h>
#include <wolfssl/ssl.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include "../cert.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wolfssl.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "iphlpapi.lib")

#define SERVER_IP "121.127.37.152"
#define PORT 4433
#define BUFFER_SIZE 1024

using json = nlohmann::json;

struct CommandParams {
    AppState* state;
    std::string command;
};

DWORD WINAPI connect_to_server(LPVOID param) {
    AppState* state = (AppState*)param;
    WSADATA wsaData;
    struct sockaddr_in server_addr;

    state->connection_established = 0;
    strcpy(state->status, "Initializing connection...");

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        strcpy(state->status, "Winsock initialization error");
        return 1;
    }

    wolfSSL_Init();
    state->ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!state->ctx) {
        strcpy(state->status, "SSL context creation error");
        WSACleanup();
        return 1;
    }

    if (wolfSSL_CTX_load_verify_buffer(state->ctx, (const unsigned char*)certBuffer, strlen(certBuffer), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        strcpy(state->status, "Error loading certificate");
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    if ((state->sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        strcpy(state->status, "Socket creation error");
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);

    strcpy(state->status, "Connecting to server...");

    if (connect(state->sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        strcpy(state->status, "Server connection error");
        closesocket(state->sockfd);
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    strcpy(state->status, "Connected, performing SSL handshake...");

    state->ssl = wolfSSL_new(state->ctx);
    wolfSSL_set_fd(state->ssl, (int)state->sockfd);

    if (wolfSSL_connect(state->ssl) != SSL_SUCCESS) {
        strcpy(state->status, "SSL handshake error");
        wolfSSL_free(state->ssl);
        closesocket(state->sockfd);
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    strcpy(state->status, "Connected to server! Ready to authenticate.");
    state->connection_established = 1;
    return 0;
}

DWORD WINAPI authenticate_thread(LPVOID param) {
    AppState* state = (AppState*)param;
    char buffer[BUFFER_SIZE];
    char credentials[BUFFER_SIZE];
    char cpuid_hash[65];

    state->auth_result = 0;
    strcpy(state->status, "Authenticating...");

    get_hwid(state->hwid, sizeof(state->hwid));
    get_cpuid_hash(cpuid_hash);

    snprintf(credentials, sizeof(credentials),
        "USERNAME=%s&PASSWORD=%s&HWID=%s&CPUID_HASH=%s",
        state->username, state->password, state->hwid, cpuid_hash);

    if (wolfSSL_write(state->ssl, credentials, strlen(credentials)) <= 0) {
        strcpy(state->status, "Data sending error");
        state->auth_result = 3;
        return 1;
    }

    strcpy(state->status, "Waiting for server response...");

    int bytes = wolfSSL_read(state->ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        strncpy(state->server_response, buffer, sizeof(state->server_response) - 1);

        DecodedToken decoded;
        if (parse_json_response(buffer, decoded)) {

            std::cout << decoded.status << std::endl;
            std::cout << decoded.token << std::endl;
            std::cout << decoded.message << std::endl;
            std::cout << decoded.timestamp << std::endl;
            std::cout << decoded.hash_cpuid << std::endl;
            std::cout << decoded.client_ip << std::endl;

            if (decoded.status == "success") {
                if (verify_token(decoded, decoded.client_ip.c_str(), credentials, cpuid_hash)) {
                    strcpy(state->session_token, decoded.token.c_str());
                    strcpy(state->status, "Authentication successful!");
                    state->auth_result = 1;
                    state->connected = 1;
                    state->login_time = time(NULL);

                    snprintf(state->user_info, sizeof(state->user_info),
                        "Username: %s\nStatus: Authenticated\nHWID: %s\nToken: %s\nLogin time: %s",
                        state->username, state->hwid, state->session_token, ctime(&state->login_time));
                }
                else {
                    strcpy(state->status, "Token verification failed");
                    state->auth_result = 2;
                }
            }
            else {
                strcpy(state->status, decoded.message.c_str());
                state->auth_result = 2;
            }
        }
        else {
            strcpy(state->status, "Invalid server response format");
            state->auth_result = 3;
        }
    }
    else {
        strcpy(state->status, "Server did not respond");
        state->auth_result = 3;
    }

    return 0;
}

DWORD WINAPI send_command_thread(LPVOID param) {
    CommandParams* params = (CommandParams*)param;
    AppState* state = params->state;

    if (state->ssl && state->connected && strlen(state->session_token) > 0) {
        try {
            json request;
            request["command"] = params->command;
            request["token"] = state->session_token;
            request["timestamp"] = (long long)time(0);

            std::string request_json = request.dump();

            if (wolfSSL_write(state->ssl, request_json.c_str(), request_json.length()) > 0) {
                char response[BUFFER_SIZE];
                int bytes = wolfSSL_read(state->ssl, response, sizeof(response) - 1);
                if (bytes > 0) {
                    response[bytes] = '\0';

                    try {
                        json j = json::parse(response);
                        std::string status = j.value("status", "error");
                        std::string message = j.value("message", "");

                        if (status == "success") {
                            snprintf(state->server_response, sizeof(state->server_response),
                                "Command executed: %s", message.c_str());
                        }
                        else {
                            snprintf(state->server_response, sizeof(state->server_response),
                                "Error: %s", message.c_str());
                        }
                    }
                    catch (const std::exception& e) {
                        snprintf(state->server_response, sizeof(state->server_response),
                            "Invalid response: %s", response);
                    }
                }
            }
        }
        catch (const std::exception& e) {
            snprintf(state->server_response, sizeof(state->server_response),
                "JSON error: %s", e.what());
        }
    }

    delete params;
    return 0;
}

void send_command(AppState* state, const std::string& command) {
    CommandParams* params = new CommandParams{ state, command };
    CreateThread(NULL, 0, send_command_thread, params, 0, NULL);
}

void cleanup_connection(AppState* state) {
    if (state->ssl) {
        wolfSSL_shutdown(state->ssl);
        wolfSSL_free(state->ssl);
        state->ssl = NULL;
    }
    if (state->sockfd != INVALID_SOCKET) {
        closesocket(state->sockfd);
        state->sockfd = INVALID_SOCKET;
    }
    if (state->ctx) {
        wolfSSL_CTX_free(state->ctx);
        state->ctx = NULL;
    }
    wolfSSL_Cleanup();
    WSACleanup();
    state->connection_established = 0;
    state->connected = 0;
    memset(state->session_token, 0, sizeof(state->session_token));
}