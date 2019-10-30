#include "stdafx.h"


static const TCHAR ENCRYPTED_TOKEN_FILE_NAME[] = _T("token.dat");
static const TCHAR VAULT_ADDR[] = _T("VAULT_ADDR");
static const DWORD MAX_VAULT_ADDR_SIZE = 8192;
static const DWORD MAX_TOKEN_SIZE = 256;
static const DWORD MAX_ENCRYPTED_TOKEN_SIZE = MAX_TOKEN_SIZE + 256;

static const BYTE HARDCODED_DPAPI_NOISE[] = {
   0x79, 0x7B, 0xE9, 0x5D, 0x6B, 0xAB, 0x37, 0x06, 0x57, 0x7D, 0x4C, 0x08,
   0x0E, 0xDF, 0x27, 0xCE, 0x10, 0x50, 0xEA, 0x9B, 0xBC, 0xA3, 0x5E, 0x6D,
   0x7B, 0x3C, 0xED, 0xC9, 0xB1, 0x0A, 0x42, 0x0F
};

#if defined(DEBUG) || defined(_DEBUG)
#define trace OutputDebugString
#else
#define trace(x)
#endif

DWORD print_windows_error(DWORD error, HANDLE output) {
    TCHAR *buffer = NULL;
    DWORD message_length = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, error, 0, (LPTSTR)&buffer, 0, NULL);

    trace(buffer);

#if defined(UNICODE) || defined(_UNICODE)
    //This is a UNICODE build, but we must output to a MCBS shell
    char *mcbs_buffer = (char*)LocalAlloc(0, message_length);
    message_length = WideCharToMultiByte(CP_ACP, 0, buffer, message_length, mcbs_buffer, message_length, NULL, NULL);

    WriteFile(output, mcbs_buffer, message_length, NULL, NULL);
    LocalFree(mcbs_buffer);
#else
    //This code branch never tested because we don't build a non-unicode version...
    WriteFile(output, buffer, message_length*sizeof(TCHAR), NULL, NULL);
#endif

    LocalFree(buffer);
    return message_length;
}

DWORD decrypt(const BYTE *encrypted, DWORD encrypted_length, BYTE *decrypted, DWORD max_decrypted_length)
{
    DWORD result = 0;

    DATA_BLOB ciphertext;
    DATA_BLOB plaintext;
    DATA_BLOB entropy;
    //CRYPTPROTECT_PROMPTSTRUCT PromptStruct;
    //LPWSTR pDescrOut = NULL;

    ciphertext.pbData = (BYTE*)encrypted;
    ciphertext.cbData = encrypted_length;

    entropy.pbData = (BYTE*)HARDCODED_DPAPI_NOISE;
    entropy.cbData = sizeof(HARDCODED_DPAPI_NOISE);

    //-------------------------------------------------------------------
    //   Begin unprotect phase.
    if (CryptUnprotectData(
        &ciphertext,
        NULL,
        &entropy,             // Optional entropy
        NULL,                 // Reserved
        NULL,                 // Optional PromptStruct
        0,                    //TODO: Support CRYPTPROTECT_VERIFY_PROTECTION
        &plaintext))
    {
        memcpy(decrypted, plaintext.pbData, MIN(plaintext.cbData, max_decrypted_length));
        LocalFree(plaintext.pbData);
        result = plaintext.cbData;
    }

    return result;
}


DWORD encrypt(const TCHAR* token, DWORD token_len, BYTE ** buffer)
{
    DWORD result = 0; //Number of bytes returned

    DATA_BLOB plaintext;
    DATA_BLOB entropy;
    DATA_BLOB ciphertext;

    BYTE *pbDataInput =(BYTE *)token;
    DWORD cbDataInput = token_len;  //Do not encrypt the null terminator, could lead to a known plain text attack
    plaintext.pbData = pbDataInput;
    plaintext.cbData = cbDataInput;

    //-------------------------------------------------------------------
    //  Initialize PromptStruct.
    /*
    CRYPTPROTECT_PROMPTSTRUCT PromptStruct;
    ZeroMemory(&PromptStruct, sizeof(PromptStruct));
    PromptStruct.cbSize = sizeof(PromptStruct);
    PromptStruct.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_PROTECT;
    PromptStruct.szPrompt = L"This is a user prompt.";
    */

    entropy.pbData = (BYTE*)HARDCODED_DPAPI_NOISE;
    entropy.cbData = sizeof(HARDCODED_DPAPI_NOISE);

    //-------------------------------------------------------------------
    //  Begin protect phase.
    if (CryptProtectData(
         &plaintext,
         NULL,                 // A description string.
         &entropy,             // Optional entropy not used.
         NULL,                 // Reserved.
         //&PromptStruct,                      // Pass a PromptStruct.
         NULL,
         CRYPTPROTECT_AUDIT,
         &ciphertext))
    {
        *buffer = ciphertext.pbData;
        result = ciphertext.cbData;
    }

    return result;
}


int store(HANDLE input)
{
    int result = 1;

    //TCHAR vault_addr[MAX_VAULT_ADDR_SIZE];
    //DWORD vault_addr_size = GetEnvironmentVariable(VAULT_ADDR, vault_addr, MAX_VAULT_ADDR_SIZE);

    if (input != INVALID_HANDLE_VALUE) {
        TCHAR token[MAX_TOKEN_SIZE];
        DWORD token_len = 0;
        if (ReadFile(input, token, MAX_TOKEN_SIZE, &token_len, NULL) && (token_len > 0)) {
            HANDLE encrypted_token_file =
                CreateFile(ENCRYPTED_TOKEN_FILE_NAME, // name of the write
                           GENERIC_WRITE,          // open for writing
                           0,                      // do not share
                           NULL,                   // default security
                           CREATE_ALWAYS,          // create and overwrite is required
                           FILE_ATTRIBUTE_NORMAL,  // normal file
                           NULL);                  // no attr. template

            if (encrypted_token_file != INVALID_HANDLE_VALUE) {
                BYTE *encrypted_buffer = NULL;
                DWORD encrypted_size = encrypt(token, token_len, &encrypted_buffer);

                //Secure erase from memory as early as we can
                //does not set last error
                SecureZeroMemory(token, sizeof(token));

                if (encrypted_size > 0)
                {
                    DWORD bytes_written = 0;
                    if(WriteFile(encrypted_token_file, encrypted_buffer, encrypted_size, &bytes_written, NULL)) {
                        result = ERROR_SUCCESS;
                    } else {
                        result = GetLastError();
                    }
                    LocalFree(encrypted_buffer);
                } else {
                    result = GetLastError();
                }
                CloseHandle(encrypted_token_file);
            } else {
                result = GetLastError();
            }
        } else {
            result = GetLastError();
        }
    }

    return result;
}

int get(HANDLE output)
{
    int result = 1;

    //TCHAR vault_addr[MAX_VAULT_ADDR_SIZE];
    //DWORD vault_addr_size = GetEnvironmentVariable(VAULT_ADDR, vault_addr, MAX_VAULT_ADDR_SIZE);

    HANDLE file = CreateFile(ENCRYPTED_TOKEN_FILE_NAME, // name of the write
                           GENERIC_READ,           // open for writing
                           0,                      // do not share
                           NULL,                   // default security
                           OPEN_EXISTING,          // create and overwrite is required
                           FILE_ATTRIBUTE_NORMAL,  // normal file
                           NULL);                  // no attr. template

    if (file != INVALID_HANDLE_VALUE)
    {
        BYTE encrypted_token[MAX_ENCRYPTED_TOKEN_SIZE];
        DWORD encrypted_token_size = GetFileSize(file, NULL);

        if (ReadFile(file, encrypted_token, MAX_ENCRYPTED_TOKEN_SIZE, &encrypted_token_size, NULL) && (encrypted_token_size > 0))
        {
            BYTE token[MAX_TOKEN_SIZE];
            DWORD read = decrypt(encrypted_token, encrypted_token_size, token, sizeof(token)/sizeof(*token));
            if (read > 0) {
                if (WriteFile(output, token, read, NULL, NULL))
                {
                    result = 0;
                }
                SecureZeroMemory(token, sizeof(token));
            }
        }
    }

    //If we failed, get Windows last error
    return result?GetLastError():ERROR_SUCCESS;
}

DWORD erase()
{
    DWORD result = DeleteFile(ENCRYPTED_TOKEN_FILE_NAME);

    if (!result) {
        result = GetLastError();
        //If the file is already gone
        if (result == ERROR_FILE_NOT_FOUND) {
            //Then that's OK
            result = ERROR_SUCCESS;
        }
    } else {
        result = ERROR_SUCCESS;
    }

    //Follow the internal convention of returning 0 on success
    return result;
}

int dispatch(const TCHAR* operation)
{
    int result = ERROR_INVALID_FUNCTION;

    if (operation && *operation)
    {
        if(_tcscmp(_T("get"), operation) == 0)
        {
            trace(_T("Vault Token Helper get operation started"));
            return get(GetStdHandle(STD_OUTPUT_HANDLE));
        } else if(_tcscmp(_T("store"), operation) == 0)
        {
            trace(_T("Vault Token Helper store operation started"));
            return store(GetStdHandle(STD_INPUT_HANDLE));
        } else if(_tcscmp(_T("erase"), operation) == 0)
        {
            trace(_T("Vault Token Helper erase operation started"));
            return erase();
        }
    }

    return result;
}


int _tmain(int argc, TCHAR *argv[])
{
    int error = 1;

    if(argc == 2)
    {
        error = dispatch(argv[1]);
        if (error) {
            print_windows_error(error, GetStdHandle(STD_ERROR_HANDLE));
        }
    }

    return error;
}

