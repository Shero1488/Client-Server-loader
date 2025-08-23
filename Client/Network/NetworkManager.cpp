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

#define SERVER_IP xorstr_("121.127.37.152")
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
    strcpy(state->status, xorstr_("Initializing connection..."));

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        strcpy(state->status, xorstr_("Winsock initialization error"));
        return 1;
    }

    wolfSSL_Init();
    state->ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!state->ctx) {
        strcpy(state->status, xorstr_("SSL context creation error"));
        WSACleanup();
        return 1;
    }

    if (wolfSSL_CTX_load_verify_buffer(state->ctx, (const unsigned char*)certBuffer, strlen(certBuffer), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        strcpy(state->status, xorstr_("Error loading certificate"));
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    if ((state->sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        strcpy(state->status, xorstr_("Socket creation error"));
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);

    strcpy(state->status, xorstr_("Connecting to server..."));

    if (connect(state->sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        strcpy(state->status, xorstr_("Server connection error"));
        closesocket(state->sockfd);
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    strcpy(state->status, xorstr_("Connected, performing SSL handshake..."));

    state->ssl = wolfSSL_new(state->ctx);
    wolfSSL_set_fd(state->ssl, (int)state->sockfd);

    if (wolfSSL_connect(state->ssl) != SSL_SUCCESS) {
        strcpy(state->status, xorstr_("SSL handshake error"));
        wolfSSL_free(state->ssl);
        closesocket(state->sockfd);
        wolfSSL_CTX_free(state->ctx);
        WSACleanup();
        return 1;
    }

    strcpy(state->status, xorstr_("Connected to server! Ready to authenticate."));
    state->connection_established = 1;
    return 0;
}

bool parse_hash_response(const char* json_str, HashCheckResponse& response) {
    try {
        json j = json::parse(json_str);

        if (j.contains(xorstr_("status")) && j.contains(xorstr_("message"))) {
            response.status = j[xorstr_("status")].get<std::string>();
            response.message = j[xorstr_("message")].get<std::string>();
            return true;
        }
    }
    catch (const json::parse_error& e) {
        std::cerr << xorstr_("JSON parse error: ") << e.what() << std::endl;
    }
    catch (const json::type_error& e) {
        std::cerr << xorstr_("JSON type error: ") << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << xorstr_("Error parsing hash response: ") << e.what() << std::endl;
    }

    return false;
}

DWORD WINAPI authenticate_thread(LPVOID param) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    std::string filename = path;

    AppState* state = (AppState*)param;
    char buffer[BUFFER_SIZE];
    char credentials[BUFFER_SIZE];
    char cpuid_hash[65];

    state->auth_result = 0;
    strcpy(state->status, xorstr_("Authenticating..."));

    get_hwid(state->hwid, sizeof(state->hwid));
    get_cpuid_hash(cpuid_hash);

    char hash_request[128];
    snprintf(hash_request, sizeof(hash_request), xorstr_("HASH_CHECK=%s"), Hasher::calculateHash(filename));

    strcpy(state->status, xorstr_("Sending hash for verification..."));

    if (wolfSSL_write(state->ssl, hash_request, strlen(hash_request)) <= 0) {
        strcpy(state->status, xorstr_("Hash sending error"));
        state->auth_result = 3;
        return 1;
    }

    strcpy(state->status, xorstr_("Waiting for hash verification..."));

    int bytes = wolfSSL_read(state->ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';

        HashCheckResponse hash_response;
        if (parse_hash_response(buffer, hash_response)) {

            if (hash_response.status == xorstr_("hash_valid")) {
                std::cout << xorstr_("Hash valid") << std::endl;

                strcpy(state->status, xorstr_("Hash verified, sending credentials..."));

                snprintf(credentials, sizeof(credentials),
                    xorstr_("USERNAME=%s&PASSWORD=%s&HWID=%s&CPUID_HASH=%s"),
                    state->username, state->password, state->hwid, cpuid_hash);

                if (wolfSSL_write(state->ssl, credentials, strlen(credentials)) <= 0) {
                    strcpy(state->status, xorstr_("Credentials sending error"));
                    state->auth_result = 3;
                    return 1;
                }

                strcpy(state->status, xorstr_("Waiting for authentication response..."));

                bytes = wolfSSL_read(state->ssl, buffer, sizeof(buffer) - 1);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    strncpy(state->server_response, buffer, sizeof(state->server_response) - 1);

                    DecodedToken decoded;
                    if (parse_json_response(buffer, decoded)) {
                        if (decoded.status == xorstr_("success")) {
                            if (verify_token(decoded, decoded.ip.c_str(), credentials, cpuid_hash)) {
                                strcpy(state->session_token, decoded.token.c_str());
                                strcpy(state->status, xorstr_("Authentication successful!"));
                                state->auth_result = 1;
                                state->connected = 1;
                                state->login_time = time(NULL);

                                snprintf(state->user_info, sizeof(state->user_info),
                                    xorstr_("Username: %s\nStatus: Authenticated\nHWID: %s\nToken: %s\nLogin time: %s"),
                                    state->username, state->hwid, state->session_token, ctime(&state->login_time));
                            }
                            else {
                                strcpy(state->status, xorstr_("Token verification failed"));
                                state->auth_result = 2;
                            }
                        }
                        else {
                            strcpy(state->status, decoded.message.c_str());
                            state->auth_result = 2;
                        }
                    }
                    else {
                        strcpy(state->status, xorstr_("Invalid server response format"));
                        state->auth_result = 3;
                    }
                }
                else {
                    strcpy(state->status, xorstr_("No authentication response from server"));
                    state->auth_result = 3;
                }
            }
            else {
                strcpy(state->status, hash_response.message.c_str());
                state->auth_result = 2;
            }
        }
        else {
            strcpy(state->status, xorstr_("Invalid hash response format"));
            state->auth_result = 3;
        }
    }
    else {
        strcpy(state->status, xorstr_("Server did not respond to hash request"));
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
            request[xorstr_("command")] = params->command;
            request[xorstr_("token")] = state->session_token;
            request[xorstr_("timestamp")] = (long long)time(0);

            std::string request_json = request.dump();

            if (wolfSSL_write(state->ssl, request_json.c_str(), request_json.length()) > 0) {
                char response[BUFFER_SIZE];
                int bytes = wolfSSL_read(state->ssl, response, sizeof(response) - 1);
                if (bytes > 0) {
                    response[bytes] = '\0';

                    try {
                        json j = json::parse(response);
                        std::string status = j.value(xorstr_("status"), xorstr_("error"));
                        std::string message = j.value(xorstr_("message"), xorstr_(""));

                        if (status == xorstr_("success")) {
                            snprintf(state->server_response, sizeof(state->server_response),
                                xorstr_("Command executed: %s"), message.c_str());
                        }
                        else {
                            snprintf(state->server_response, sizeof(state->server_response),
                                xorstr_("Error: %s"), message.c_str());
                        }
                    }
                    catch (const std::exception& e) {
                        snprintf(state->server_response, sizeof(state->server_response),
                            xorstr_("Invalid response: %s"), response);
                    }
                }
            }
        }
        catch (const std::exception& e) {
            snprintf(state->server_response, sizeof(state->server_response),
                xorstr_("JSON error: %s"), e.what());
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

void perform_auto_login(AppState* state, HANDLE* auth_thread) {
    if (state->auto_login &&
        state->username[0] != '\0' &&
        state->password[0] != '\0' &&
        !state->connected &&
        state->connection_established &&
        *auth_thread == NULL) {

        strcpy(state->status, xorstr_("Performing auto-login..."));
        *auth_thread = CreateThread(NULL, 0, authenticate_thread, state, 0, NULL);
    }
}