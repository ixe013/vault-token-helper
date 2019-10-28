#include "stdafx.h"


typedef std::basic_string<TCHAR>   tstring;

static const TCHAR ENCRYPTED_TOKEN_FILE_NAME[] = _T("token.dat");
static const TCHAR VAULT_ADDR[] = _T("VAULT_ADDR");
static const DWORD MAX_VAULT_ADDR_SIZE = 8192;
static const DWORD MAX_TOKEN_SIZE = 256;
static const BYTE HARDCODED_DPAPI_NOISE[] = {
	0x79, 0x7B, 0xE9, 0x5D, 0x6B, 0xAB, 0x37, 0x06, 0x57, 0x7D, 0x4C, 0x08,
	0x0E, 0xDF, 0x27, 0xCE, 0x10, 0x50, 0xEA, 0x9B, 0xBC, 0xA3, 0x5E, 0x6D,
	0x7B, 0x3C, 0xED, 0xC9, 0xB1, 0x0A, 0x42, 0x0F
};

std::string decrypt(const std::vector<char>& encrypted)
{
    std::string result;
    // Copyright (C) Microsoft.  All rights reserved.
    // Encrypt data from DATA_BLOB DataIn to DATA_BLOB DataOut.
    // Then decrypt to DATA_BLOB DataVerify.

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    DATA_BLOB DataOut;
    DATA_BLOB DataVerify;
    DATA_BLOB entropy;
    //CRYPTPROTECT_PROMPTSTRUCT PromptStruct;
    //LPWSTR pDescrOut = NULL;

    DataOut.pbData = (BYTE*)&encrypted[0];
    DataOut.cbData = encrypted.size();

    entropy.pbData = (BYTE*)HARDCODED_DPAPI_NOISE;
    entropy.cbData = sizeof(HARDCODED_DPAPI_NOISE);

    //-------------------------------------------------------------------
    //   Begin unprotect phase.
    if (CryptUnprotectData(
        &DataOut,
        NULL,
        &entropy,             // Optional entropy
        NULL,                 // Reserved
        NULL,                 // Optional PromptStruct
        0,
        &DataVerify))
    {
        result = std::string((const char *)DataVerify.pbData, DataVerify.cbData);
        LocalFree(DataVerify.pbData);
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


int store(std::istream &input)
{
    int result = 1;
    
    //TCHAR vault_addr[MAX_VAULT_ADDR_SIZE];
    //DWORD vault_addr_size = GetEnvironmentVariable(VAULT_ADDR, vault_addr, MAX_VAULT_ADDR_SIZE);
    
    HANDLE standard_input = GetStdHandle(STD_INPUT_HANDLE);

    if (standard_input != INVALID_HANDLE_VALUE) {
        TCHAR token[MAX_TOKEN_SIZE];
        DWORD token_len = 0;
        if (ReadFile(standard_input, token, MAX_TOKEN_SIZE, &token_len, NULL) && (token_len > 0)) {
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
                if (encrypted_size > 0) 
                {
                    DWORD bytes_written = 0;
                    if(WriteFile(encrypted_token_file, encrypted_buffer, encrypted_size, &bytes_written, NULL)) {
                        result = 0;
                    }
                    LocalFree(encrypted_buffer);  //Could leak if file.write throws, but process is too short lived to care
                }
            }
        }
    }

    return result;
}

int get(std::ostream &output)
{
    int result = 1;
    
    //TCHAR vault_addr[MAX_VAULT_ADDR_SIZE];
    //DWORD vault_addr_size = GetEnvironmentVariable(VAULT_ADDR, vault_addr, MAX_VAULT_ADDR_SIZE);
    
    std::ifstream file;
               
    file.open(ENCRYPTED_TOKEN_FILE_NAME, std::ios::binary);

    if(file.is_open())
    {
        std::streamsize size;
        file.seekg(0, std::ios::end);
        size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        if (file.read(buffer.data(), size))
        {
            std::string token = decrypt(buffer);
            output << token;
            /* worked! */
            result = 0;
        }
    }

    return result;
}

int erase() 
{
    int result = 1;
    DeleteFile(ENCRYPTED_TOKEN_FILE_NAME);
    return result;
}

int dispatch(const TCHAR* operation)
{
    int result = 1;

    if (operation && *operation) 
    {
        if(_tcscmp(_T("get"), operation) == 0)
        {
            return get(std::cout);
        } else if(_tcscmp(_T("store"), operation) == 0) 
        {
            return store(std::cin);
        } else if(_tcscmp(_T("erase"), operation) == 0) 
        {
            return erase();
        } 
    }

    return result;
}


int _tmain(int argc, TCHAR *argv[])
{
    int result = 1;

    if(argc == 2)
    {
        dispatch(argv[1]);
    }

    return result;
}

