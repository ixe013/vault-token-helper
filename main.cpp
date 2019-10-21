#include <windows.h>
#include <tchar.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <stdio.h>
#include <Wincrypt.h>

void MyHandleError(const char *s);

typedef std::basic_string<TCHAR>   tstring;

static const TCHAR VAULT_ADDR[] = _T("VAULT_ADDR");
static const DWORD MAX_VAULT_ADDR_SIZE = 8192;

int coucou()
{
    open(NULL, 0);
    close(42);
    return 42;
}

DWORD decrypt(const std::string& token, BYTE ** buffer)
{
    DWORD result = 0; //Number of bytes returned

    DATA_BLOB plaintext;
    //DATA_BLOB entropy;
    DATA_BLOB ciphertext;

    BYTE *pbDataInput =(BYTE *)token.c_str();
    DWORD cbDataInput = token.size();  //Do not encrypt the null terminator, could lead to a known plain text attack
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
    /*/
    //*/

    //-------------------------------------------------------------------
    //  Begin protect phase.
    if (CryptProtectData(
         &plaintext, 
         NULL,                 // A description string. 
         NULL,                 // Optional entropy not used.
         NULL,                 // Reserved.
         //&PromptStruct,                      // Pass a PromptStruct.
         NULL,
         CRYPTPROTECT_AUDIT,
         &ciphertext));
    {
        *buffer = ciphertext.pbData;
        result = ciphertext.cbData;
    }

    return result;
}


DWORD encrypt(const std::string& token, BYTE ** buffer)
{
    DWORD result = 0; //Number of bytes returned

    DATA_BLOB plaintext;
    //DATA_BLOB entropy;
    DATA_BLOB ciphertext;

    BYTE *pbDataInput =(BYTE *)token.c_str();
    DWORD cbDataInput = token.size();  //Do not encrypt the null terminator, could lead to a known plain text attack
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
    /*/
    //*/

    //-------------------------------------------------------------------
    //  Begin protect phase.
    if (CryptProtectData(
         &plaintext, 
         NULL,                 // A description string. 
         NULL,                 // Optional entropy not used.
         NULL,                 // Reserved.
         //&PromptStruct,                      // Pass a PromptStruct.
         NULL,
         CRYPTPROTECT_AUDIT,
         &ciphertext));
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
    
    std::string token;

    input >> token;

    std::ofstream file;

    file.open("token.dat", std::ios::binary);

    if(file.is_open())
    {
        BYTE *encrypted_buffer = NULL;
        DWORD encrypted_size = encrypt(token, &encrypted_buffer);
        if (encrypted_size > 0) 
        {
            file.write((const char *)encrypted_buffer, encrypted_size);
            LocalFree(encrypted_buffer);  //Could leak if file.write throws, but process is too short lived to care
        }
    }

    return result;
}

int get(FILE *) 
{
    int result = 1;
    return result;
}

int erase() 
{
    int result = 1;
    return result;
}

int dispatch(const TCHAR* operation)
{
    int result = 1;

    if (operation && *operation) 
    {
        if(_tcscmp(_T("get"), operation) == 0)
        {
            return get(stdin);
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

int old()
{
    // Copyright (C) Microsoft.  All rights reserved.
    // Encrypt data from DATA_BLOB DataIn to DATA_BLOB DataOut.
    // Then decrypt to DATA_BLOB DataVerify.

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    DATA_BLOB DataIn;
    DATA_BLOB DataOut;
    DATA_BLOB DataVerify;
    BYTE *pbDataInput =(BYTE *)"Hello world of data protection.";
    DWORD cbDataInput = strlen((char *)pbDataInput)+1;
    DataIn.pbData = pbDataInput;    
    DataIn.cbData = cbDataInput;
    CRYPTPROTECT_PROMPTSTRUCT PromptStruct;
    LPWSTR pDescrOut = NULL;

    //-------------------------------------------------------------------
    //  Begin processing.
    _tprintf(_T("The data to be encrypted is: %s\n"),pbDataInput);

    //-------------------------------------------------------------------
    //  Initialize PromptStruct.
    ZeroMemory(&PromptStruct, sizeof(PromptStruct));
    PromptStruct.cbSize = sizeof(PromptStruct);
    PromptStruct.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_PROTECT;
    PromptStruct.szPrompt = L"This is a user prompt.";

    //-------------------------------------------------------------------
    //  Begin protect phase.
    if(CryptProtectData(
         &DataIn,
         L"This is the description string.", // A description string. 
         NULL,                               // Optional entropy not used.
         NULL,                               // Reserved.
         &PromptStruct,                      // Pass a PromptStruct.
         CRYPTPROTECT_AUDIT,
         &DataOut))
    {
         _tprintf(_T("The encryption phase worked. \n"));
    }
    else
    {
        MyHandleError("Encryption error!");
    }

    //-------------------------------------------------------------------
    //   Begin unprotect phase.
    if (CryptUnprotectData(
        &DataOut,
        &pDescrOut,
        NULL,                 // Optional entropy
        NULL,                 // Reserved
        &PromptStruct,        // Optional PromptStruct
        0,
        &DataVerify))
    {
         _tprintf(_T("The decrypted data is: %s\n"), DataVerify.pbData);
         _tprintf(_T("The description of the data was: %S\n"),pDescrOut);
    }
    else
    {
        MyHandleError("Decryption error!");
    }
    //-------------------------------------------------------------------
    // At this point, memcmp could be used to compare DataIn.pbData and 
    // DataVerify.pbDate for equality. If the two functions worked
    // correctly, the two byte strings are identical. 

    //-------------------------------------------------------------------
    //  Clean up.
    LocalFree(pDescrOut);
    LocalFree(DataOut.pbData);
    LocalFree(DataVerify.pbData);

    return 0;
} // End of main

//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(const char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %ld.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError

int _tmain(int argc, TCHAR *argv[])
{
    int result = 1;

    if(argc == 2)
    {
        dispatch(argv[1]);
    }
    else if(argc == 1234)
    {
        coucou();
    }

    return result;
}

