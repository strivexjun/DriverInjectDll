// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <tchar.h>
#include <Shlwapi.h>

#pragma comment(lib,"Shlwapi.lib")

DWORD __stdcall WorkThread(LPVOID lpram)
{
	TCHAR modulePtah[MAX_PATH];
	TCHAR exeName[MAX_PATH];
	GetModuleFileName(NULL, modulePtah, MAX_PATH);
	_tcscat(modulePtah, _T(" -> Inject OK!"));
	MessageBox(NULL, modulePtah, _T("Info"), MB_ICONINFORMATION);

	_tcscpy(exeName, modulePtah);
	PathStripPath(exeName);
	if (_tcsicmp(exeName, _T("xxxxxxx.exe")) != 0)
	{
		return 0;
	}

	//
	// TODO
	//




	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		HANDLE hTread = CreateThread(NULL, NULL, WorkThread, NULL, NULL, NULL);
		if (hTread)
		{
			CloseHandle(hTread);
		}
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

