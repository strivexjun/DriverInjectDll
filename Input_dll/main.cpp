#include <windows.h>
#include <iostream>
#include <devioctl.h>

#include "dll_x86.h"
#include "dll_x64.h"


#define IOCTL_SET_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)



int main()
{
	BOOL	result;
	DWORD	returnLen;
	char	output;

	HANDLE	hDevice = CreateFile(L"\\\\.\\CrashDumpUpload", 
								 NULL,
								 NULL, 
								 NULL, 
								 OPEN_EXISTING, 
								 NULL,
								 NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		std::cout << "connect device fail." << std::endl;
		goto __exit;
	}

	result = DeviceIoControl(hDevice,
							 IOCTL_SET_INJECT_X86DLL,
							 &dll_x86,
							 sizeof(dll_x86),
							 &output,
							 sizeof(char),
							 &returnLen,
							 NULL);

	std::cout << (result ? "ok x86dll" : "fail x86dll") << std::endl;

	result = DeviceIoControl(hDevice,
							 IOCTL_SET_INJECT_X64DLL,
							 &dll_x64,
							 sizeof(dll_x64),
							 &output,
							 sizeof(char),
							 &returnLen,
							 NULL);

	std::cout << (result ? "ok x64dll" : "fail x64dll") << std::endl;


__exit:
	getchar();
	return 0;
}