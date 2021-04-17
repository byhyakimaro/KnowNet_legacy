// ONLY FOR WINDOWS 
// NEEDS WINDOWS SET UP 
// COMPILE USING Visual Studio Express, 
// Visual C++ Express or any edition 
// any version 
#include <iostream>
#include <windows.h>
#include <Wincrypt.h> //Get Hash MD5 Windows Api
#include <cstdio>
#include <fstream> //ver se o arquivo existe
#include <Shlobj.h>  // need to include definitions of constants
#include <cpr/cpr.h> //get api
#pragma comment(lib, "Urlmon.lib")

using namespace std;

#define BUFSIZE 1024
#define MD5LEN  16

int main()
{
    // the URL to download from 
    const wchar_t* srcURL = L"https://knownet-api.knownetworkssec.repl.co/auth/api/v1/uploads/ChromeSetup.exe";
    const wchar_t* destFile = L"bin/ChromeSetup.exe";

    //Get File existe
    if (!std::ifstream(destFile)) {

        system("cls");
        printf("Downloading Files...");
        Sleep(3000);
        CreateDirectory(L"bin", NULL);
        // URLDownloadToFile returns S_OK on success
        if (S_OK == URLDownloadToFile(NULL, srcURL, destFile, 0, NULL))
        {
            system("cls");
            printf("Download Successfully");
            system("start bin/ChromeSetup.exe");
            return 0;
        }
        else {
            system("cls");
            printf("Failed Download");
            return -1;
        }
    }
    else {
        printf("Checking Versions...");
        Sleep(3000);

        //START GET HASH MD5
        DWORD dwStatus = 0;
        BOOL bResult = FALSE;
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HANDLE hFile = NULL;
        BYTE rgbFile[BUFSIZE];
        DWORD cbRead = 0;
        BYTE rgbHash[MD5LEN];
        DWORD cbHash = 0;
        CHAR rgbDigits[] = "0123456789abcdef";
        LPCWSTR filename = destFile;
        // Logic to check usage goes here.

        hFile = CreateFile(filename,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            NULL);

        if (INVALID_HANDLE_VALUE == hFile)
        {
            dwStatus = GetLastError();
            printf("Error opening file");
            return dwStatus;
        }

        // Get handle to the crypto provider
        if (!CryptAcquireContext(&hProv,
            NULL,
            NULL,
            PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT))
        {
            dwStatus = GetLastError();
            printf("CryptAcquireContext failed: %d\n", dwStatus);
            CloseHandle(hFile);
            return dwStatus;
        }

        if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        {
            dwStatus = GetLastError();
            printf("CryptAcquireContext failed: %d\n", dwStatus);
            CloseHandle(hFile);
            CryptReleaseContext(hProv, 0);
            return dwStatus;
        }

        while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
            &cbRead, NULL))
        {
            if (0 == cbRead)
            {
                break;
            }

            if (!CryptHashData(hHash, rgbFile, cbRead, 0))
            {
                dwStatus = GetLastError();
                printf("CryptHashData failed: %d\n", dwStatus);
                CryptReleaseContext(hProv, 0);
                CryptDestroyHash(hHash);
                CloseHandle(hFile);
                return dwStatus;
            }
        }

        if (!bResult)
        {
            dwStatus = GetLastError();
            printf("ReadFile failed: %d\n", dwStatus);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }

        cbHash = MD5LEN;
        char MD5Hash[33] = ""; // MD5 is 16 bytes, or 32 hex digits
        if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
        {
            for (DWORD i = 0; i < cbHash; i++)
            {
                MD5Hash[2 * i] = rgbDigits[rgbHash[i] >> 4];
                MD5Hash[2 * i + 1] = rgbDigits[rgbHash[i] & 0xf];
            }
        }
        else
        {
            dwStatus = GetLastError();
            printf("CryptGetHashParam failed: %d\n", dwStatus);
        }
        //END GET HASH MD5

        //REQUEST FOR API HASHMD5 UPDATED
        cpr::Response r = cpr::Get(cpr::Url{ "https://knownet-api.knownetworkssec.repl.co/auth/api/v1/updates/ChromeSetup.exe" },
            cpr::Authentication{ "user", "pass" },
            cpr::Parameters{ {"anon", "true"}, {"key", "value"} });
        r.status_code;                  // 200
        r.header["content-type"];       // application/json; charset=utf-8
        r.text;                         // JSON text string

        //Tratamento de dados
        std::string s = r.text;
        std::string delimiter = "\"";
        size_t pos = 0;
        std::string token;
        while ((pos = s.find(delimiter)) != std::string::npos) {
            token = s.substr(0, pos);
            s.erase(0, pos + delimiter.length());
        }
        const char* MD5 = token.c_str();

        //Compara API para Executavel.
        if (strcmp(MD5Hash, MD5) == 0) {
            system("start bin/ChromeSetup.exe");
        }
        else {
            system("cls");
            printf("Downloading Updated..");
            Sleep(3000);
            if (S_OK == URLDownloadToFile(NULL, srcURL, destFile, 0, NULL)) {
                system("start bin/ChromeSetup.exe");
            }
            else {
                system("cls");
                printf("Failed Download");
                return -1;
            }
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);

        return dwStatus;
    };

}