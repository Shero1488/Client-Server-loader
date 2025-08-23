#include "CredentialsManager.h"
#include <fstream>
#include <filesystem>
#include <windows.h>
#include <shlobj.h>
#include <cstring>

namespace fs = std::filesystem;

std::string CredentialsManager::GetCredentialsPath() {
    char appdata_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata_path))) {
        std::string folder_path = std::string(appdata_path) + xorstr_("\\SSLClient\\");
        if (!fs::exists(folder_path)) {
            fs::create_directories(folder_path);
        }
        return folder_path + xorstr_("credentials.dat");
    }
    return xorstr_("credentials.dat");
}

std::string simple_encrypt_decrypt(const std::string& input, const std::string& key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i % key.size()];
    }
    return output;
}

void CredentialsManager::SaveCredentials(AppState* state) {
    if (!state->save_creds) {
        std::string cred_path = GetCredentialsPath();
        if (fs::exists(cred_path)) {
            fs::remove(cred_path);
        }
        return;
    }

    std::ofstream file(GetCredentialsPath(), std::ios::binary);
    if (file.is_open()) {
        std::string encryption_key = xorstr_("ssl_client_encryption_key_2025");

        std::string username_str(state->username);
        std::string password_str(state->password);

        std::string encrypted_user = simple_encrypt_decrypt(username_str, encryption_key);
        std::string encrypted_pass = simple_encrypt_decrypt(password_str, encryption_key);

        size_t user_len = encrypted_user.size();
        size_t pass_len = encrypted_pass.size();

        file.write(reinterpret_cast<const char*>(&user_len), sizeof(user_len));
        file.write(encrypted_user.c_str(), user_len);

        file.write(reinterpret_cast<const char*>(&pass_len), sizeof(pass_len));
        file.write(encrypted_pass.c_str(), pass_len);

        file.write(reinterpret_cast<const char*>(&state->auto_login), sizeof(state->auto_login));
        file.write(reinterpret_cast<const char*>(&state->save_creds), sizeof(state->save_creds));

        file.close();
    }
}

void CredentialsManager::LoadCredentials(AppState* state) {
    std::string cred_path = GetCredentialsPath();
    if (!fs::exists(cred_path)) {
        return;
    }

    std::ifstream file(cred_path, std::ios::binary);
    if (file.is_open()) {
        try {
            std::string encryption_key = xorstr_("ssl_client_encryption_key_2025");

            size_t user_len;
            file.read(reinterpret_cast<char*>(&user_len), sizeof(user_len));
            std::string encrypted_user(user_len, '\0');
            file.read(&encrypted_user[0], user_len);

            size_t pass_len;
            file.read(reinterpret_cast<char*>(&pass_len), sizeof(pass_len));
            std::string encrypted_pass(pass_len, '\0');
            file.read(&encrypted_pass[0], pass_len);

            std::string username_str = simple_encrypt_decrypt(encrypted_user, encryption_key);
            std::string password_str = simple_encrypt_decrypt(encrypted_pass, encryption_key);

            strncpy(state->username, username_str.c_str(), sizeof(state->username) - 1);
            strncpy(state->password, password_str.c_str(), sizeof(state->password) - 1);
            state->username[sizeof(state->username) - 1] = '\0';
            state->password[sizeof(state->password) - 1] = '\0';

            file.read(reinterpret_cast<char*>(&state->auto_login), sizeof(state->auto_login));
            file.read(reinterpret_cast<char*>(&state->save_creds), sizeof(state->save_creds));

        }
        catch (...) {
            state->username[0] = '\0';
            state->password[0] = '\0';
            state->auto_login = false;
            state->save_creds = false;
        }
        file.close();
    }
}