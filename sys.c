#include "sys.h"

NTSTATUS SysGetSystemVersion(PSYSTEM_VERSION pSysVer)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOEXW OsVerSionInfoExW;

	if (pSysVer == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory((PVOID)&OsVerSionInfoExW, sizeof(RTL_OSVERSIONINFOEXW));

	OsVerSionInfoExW.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OsVerSionInfoExW);
	if (NT_SUCCESS(status))
	{
		if (OsVerSionInfoExW.dwMajorVersion == 10 && OsVerSionInfoExW.dwMinorVersion == 0)
		{
			if(OsVerSionInfoExW.wProductType== VER_NT_WORKSTATION)
				pSysVer->SystemVersion = SystemVersionWin10;
			else
				pSysVer->SystemVersion = SystemVersionWinServer2016;
		}
		else if (OsVerSionInfoExW.dwMajorVersion == 6 && OsVerSionInfoExW.dwMinorVersion == 3)
		{
			if (OsVerSionInfoExW.wProductType == VER_NT_WORKSTATION)
				pSysVer->SystemVersion = SystemVersionWin8_1;
			else
				pSysVer->SystemVersion = SystemVersionWinServer2012R2;
		}
		else if (OsVerSionInfoExW.dwMajorVersion == 6 && OsVerSionInfoExW.dwMinorVersion == 2)
		{
			if (OsVerSionInfoExW.wProductType == VER_NT_WORKSTATION)
				pSysVer->SystemVersion = SystemVersionWin8;
			else
				pSysVer->SystemVersion = SystemVersionWinServer2012;
		}
		else if (OsVerSionInfoExW.dwMajorVersion == 6 && OsVerSionInfoExW.dwMinorVersion == 1)
		{
			if (OsVerSionInfoExW.wProductType == VER_NT_WORKSTATION)
				pSysVer->SystemVersion = SystemVersionWin7;
			else
				pSysVer->SystemVersion = SystemVersionWinServer2008R2;
		}
		else if (OsVerSionInfoExW.dwMajorVersion == 6 && OsVerSionInfoExW.dwMinorVersion == 0)
		{
			if (OsVerSionInfoExW.wProductType == VER_NT_WORKSTATION)
				pSysVer->SystemVersion = SystemVersionWinVista;
			else
				pSysVer->SystemVersion = SystemVersionWinServer2008;
		}
		else if (OsVerSionInfoExW.dwMajorVersion == 5 && OsVerSionInfoExW.dwMinorVersion == 2)
		{
			if (OsVerSionInfoExW.wSuiteMask & VER_SUITE_WH_SERVER)
				pSysVer->SystemVersion = SystemVersionWinHomeServer;
		}
		else if (OsVerSionInfoExW.dwMajorVersion == 5 && OsVerSionInfoExW.dwMinorVersion == 1)
		{
			pSysVer->SystemVersion = SystemVersionWinxp;
		}
		else if (OsVerSionInfoExW.dwMajorVersion == 5 && OsVerSionInfoExW.dwMinorVersion == 0)
		{
			pSysVer->SystemVersion = SystemVersionWin2000;
		}
		else
			pSysVer->SystemVersion = SystemVersionUnkonw;

		pSysVer->BuildNumber = OsVerSionInfoExW.dwBuildNumber;
		return status;
	}
	else
	{
		return status;
	}
}
