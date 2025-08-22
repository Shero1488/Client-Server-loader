#pragma once
#include <winsock2.h>
#include <wolfssl/ssl.h>
#include <time.h>

#define TOKEN_SIZE 33

typedef struct AppState {
    char username[100];
    char password[100];
    char status[256];
    char server_response[512];
    char hwid[256];
    char session_token[TOKEN_SIZE];
    int auth_result;
    int connected;
    bool show_password;
    int registered;
    int current_page;
    char user_info[1024];
    time_t login_time;
    WOLFSSL* ssl;
    SOCKET sockfd;
    WOLFSSL_CTX* ctx;
    int connection_established;
} AppState;