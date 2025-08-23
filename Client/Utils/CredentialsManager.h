#pragma once
#include "../App/AppState.h"
#include <string>

class CredentialsManager {
public:
    static void SaveCredentials(AppState* state);
    static void LoadCredentials(AppState* state);
    static std::string GetCredentialsPath();
};