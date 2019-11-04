// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#if !defined(UNICODE) && !defined(_UNICODE)
#error This program must be compiled as Unicode
#endif

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Wincrypt.h>
#include <Shlobj.h>
#include <Knownfolders.h>


#define MIN(x,y) (x<y?x:y)
