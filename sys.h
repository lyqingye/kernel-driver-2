
#ifndef SYS_HEAD
#define SYS_HEAD

#include "pstdint.h"

#pragma once

// System Version Enumaretion Class
enum SystemVersionClass
{
	SystemVersionUnkonw,
	SystemVersionWin2000,
	SystemVersionWinxp,
	SystemVersionWinxpX64Edition,	//No suport
	SystemVersionWinServer2003,		//No suport
	SystemVersionWinHomeServer,
	SystemVersionWinServer2003R2,   //No suport
	SystemVersionWinVista,
	SystemVersionWinServer2008,
	SystemVersionWinServer2008R2,
	SystemVersionWin7,
	SystemVersionWinServer2012,
	SystemVersionWin8,
	SystemVersionWinServer2012R2,
	SystemVersionWin8_1,
	SystemVersionWinServer2016,
	SystemVersionWin10
};

typedef struct _SYSTEM_VERSION {
	ULONG BuildNumber;
	enum SystemVersionClass SystemVersion;
}SYSTEM_VERSION,*PSYSTEM_VERSION;

// Define Max System version value
#define SYS_MAX_SYSTEM_VERSION SystemVersionWin10_16299

// Get system version 
// Parameters:
//		pSysVer			[Out]	A pointer to the system versionn struct
NTSTATUS __fastcall SysGetSystemVersion(PSYSTEM_VERSION pSysVer);

#endif