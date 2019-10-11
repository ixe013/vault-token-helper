#include <windows.h>

#include <stdio.h>
#include <tchar.h>
#include <Wincrypt.h>

void MyHandleError(const char *s);

int store(FILE *) 
{
    int result = 1;
    printf(_T("storing\n"));
    return result;
}

int get(FILE *) 
{
    int result = 1;
    printf(_T("get\n"));
    return result;
}

int erase() 
{
    int result = 1;
    printf(_T("erase\n"));
    return result;
}

int dispatch(const TCHAR* operation)
{
    int result = 1;

    if (operation && *operation) 
    {
        if(_tcscmp("get", operation) == 0)
        {
            return get(stdin);
        } else if(_tcscmp("store", operation) == 0) 
        {
            return store(stdin);
        } else if(_tcscmp("erase", operation) == 0) 
        {
            return erase();
        } 
    }

    return result;
}

int main(int argc, const TCHAR *argv[])
{
    int result = 1;

    if(argc == 2)
    {
        dispatch(argv[1]);
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
    printf("The data to be encrypted is: %s\n",pbDataInput);

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
         0,
         &DataOut))
    {
         printf("The encryption phase worked. \n");
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
         printf("The decrypted data is: %s\n", DataVerify.pbData);
         printf("The description of the data was: %S\n",pDescrOut);
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
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError

