#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <wolfssl/ssl.h>
#include <time.h>
#include <sys/utsname.h>
#include <jansson.h>

#define PORT 4433
#define BUFFER_SIZE 1024
#define PHP_URL "https://prometh.fun/api/auth.php"
#define TOKEN_SIZE 33

void die(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

struct string {
    char *ptr;
    size_t len;
};

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(s->len+1);
    
    if (s->ptr == NULL)
        die("malloc() failed");

    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s) {
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);

    if (s->ptr == NULL)
        die("realloc() failed");
    
    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;
    
    return size*nmemb;
}

void generate_md5_hash(const char* input, char* output) {
    unsigned int hash[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    
    for (size_t i = 0; input[i] != '\0'; i++) {
        hash[i % 4] = (hash[i % 4] << 5) | (hash[i % 4] >> 27);
        hash[i % 4] ^= input[i];
        hash[i % 4] += 0x9E3779B9;
    }
    
    for (int i = 0; i < 4; i++)
        sprintf(output + (i * 8), "%08x", hash[i]);
    
    output[32] = '\0';
}

char* create_json_response(int success, const char* token, const char* message, 
                          const char* cpuid_hash, time_t timestamp, const char* client_ip) {
    json_t *root = json_object();
    
    json_object_set_new(root, "status", json_string(success ? "success" : "error"));
    
    if (token)
        json_object_set_new(root, "token", json_string(token));
    
    if (message)
        json_object_set_new(root, "message", json_string(message));
    
    json_object_set_new(root, "timestamp", json_integer(timestamp));
    
    if (cpuid_hash)
        json_object_set_new(root, "hash_cpuid", json_string(cpuid_hash));

    if (client_ip)
        json_object_set_new(root, "client_ip", json_string(client_ip));
    
    char *json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    
    return json_str;
}

void generate_token(char* token, const char* client_ip, const char* credentials, 
                   const char* cpuid_hash, time_t timestamp) {
    char hash_input[1024];
    snprintf(hash_input, sizeof(hash_input), "%s%s%s%ld", 
             client_ip, credentials, cpuid_hash, timestamp);
    generate_md5_hash(hash_input, token);
}

const char* extract_cpuid_hash(const char* credentials) {
    const char* cpuid_ptr = strstr(credentials, "CPUID_HASH=");
    if (cpuid_ptr) {
        cpuid_ptr += 11;
        const char* end_ptr = strchr(cpuid_ptr, '&');
        if (!end_ptr) end_ptr = cpuid_ptr + strlen(cpuid_ptr);
        
        static char hash[65];
        size_t len = end_ptr - cpuid_ptr;
        if (len > sizeof(hash) - 1) len = sizeof(hash) - 1;
        strncpy(hash, cpuid_ptr, len);
        hash[len] = '\0';
        return hash;
    }
    return NULL;
}

int verify_with_php(const char *credentials) {
    CURL *curl;
    CURLcode res;
    struct string response;
    int auth_result = -1;
    
    init_string(&response);
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, PHP_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, credentials);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            auth_result = -1;
        } else {
            if (strstr(response.ptr, "SUCCESS") != NULL)
                auth_result = 1;
            else if (strstr(response.ptr, "HWID_REGISTERED") != NULL)
                auth_result = 2;
            else if (strstr(response.ptr, "HWID_MISMATCH") != NULL)
                auth_result = 3;
            else if (strstr(response.ptr, "FAILED") != NULL)
                auth_result = 0;
            else
                auth_result = -1;
        }
        
        curl_easy_cleanup(curl);
    }
    
    curl_global_cleanup();
    free(response.ptr);
    
    return auth_result;
}

int main() {
    int sockfd, clientfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    wolfSSL_Init();
    
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (!ctx)
        die("Error creating SSL context");
    
    if (wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        die("Error loading certificate");
    
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        die("Error loading private key");
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        die("Error creating socket");
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        die("Error binding socket");
    
    if (listen(sockfd, 5) < 0)
        die("Error listening");
    
    printf("Server started on port %d\n", PORT);
    printf("Waiting for connections...\n");
    
    while (1) {
        if ((clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len)) < 0)
            die("Error accepting connection");
        
        char* client_ip = inet_ntoa(client_addr.sin_addr);
        printf("Client connected: %s\n", client_ip);
        
        WOLFSSL* ssl = wolfSSL_new(ctx);
        wolfSSL_set_fd(ssl, clientfd);
        
        if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
            fprintf(stderr, "SSL handshake error\n");
            wolfSSL_free(ssl);
            close(clientfd);
            continue;
        }
        
        int bytes = wolfSSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received auth request: %s\n", buffer);
            
            int auth_result = verify_with_php(buffer);
            const char* cpuid_hash = extract_cpuid_hash(buffer);
            
            time_t timestamp = time(0);
            
            char* json_response;
            if (auth_result == 1 || auth_result == 2) {
                char token[TOKEN_SIZE];
                generate_token(token, client_ip, buffer, cpuid_hash, timestamp);
                
                json_response = create_json_response(1, token, 
                    auth_result == 2 ? "New device registered" : "Authentication successful",
                    cpuid_hash, timestamp, client_ip);
                
		        printf(json_response);

                printf("\nAuthentication successful for %s\n", client_ip);
            } else {
                const char* message = (auth_result == 3) ? "HWID mismatch" : "Authentication failed";
                json_response = create_json_response(0, NULL, message, cpuid_hash, timestamp, client_ip);
                printf("Authentication failed for %s: %s\n", client_ip, message);
            }
            
            wolfSSL_write(ssl, json_response, strlen(json_response));
            free(json_response);
        }
        
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(clientfd);
    }
    
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(sockfd);
    
    return 0;
}