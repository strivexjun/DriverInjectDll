#include <windows.h>
#include <iostream>
#include <devioctl.h>

#define IOCTL_SET_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)


PVOID MyReadFile(WCHAR* fileName, PULONG fileSize)
{
	HANDLE fileHandle = NULL;
	DWORD readd = 0;
	PVOID fileBufPtr = NULL;

	fileHandle = CreateFile(
		fileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		*fileSize = 0;
		return NULL;
	}

	*fileSize = GetFileSize(fileHandle, NULL);

	fileBufPtr = calloc(1, *fileSize);

	if (!ReadFile(fileHandle, fileBufPtr, *fileSize, &readd, NULL))
	{
		free(fileBufPtr);
		fileBufPtr = NULL;
		*fileSize = 0;
	}

	CloseHandle(fileHandle);
	return fileBufPtr;

}


int main()
{
	BOOL	result;
	DWORD	returnLen;
	char	output;

	HANDLE	hDevice = NULL;

	PVOID	dllx64Ptr = NULL;
	PVOID	dllx86Ptr = NULL;

	ULONG	dllx64Size = 0;
	ULONG	dllx86Size = 0;

	hDevice = CreateFile(L"\\\\.\\CrashDumpUpload",
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


	dllx64Ptr = MyReadFile(L"MyDll_x64.dll", &dllx64Size);
	if (dllx64Ptr == NULL)
	{
		std::cout << "can not read MyDll_x64.dll." << std::endl;
		goto __exit;
	}

	dllx86Ptr = MyReadFile(L"MyDll_x86.dll", &dllx86Size);
	if (dllx86Ptr == NULL)
	{
		std::cout << "can not read MyDll_x86.dll." << std::endl;
		goto __exit;
	}

	result = DeviceIoControl(
		hDevice,
		IOCTL_SET_INJECT_X86DLL,
		dllx86Ptr,
		dllx86Size,
		&output,
		sizeof(char),
		&returnLen,
		NULL);

	std::cout << (result ? "ok x86dll" : "fail x86dll") << std::endl;

	result = DeviceIoControl(
		hDevice,
		IOCTL_SET_INJECT_X64DLL,
		dllx64Ptr,
		dllx64Size,
		&output,
		sizeof(char),
		&returnLen,
		NULL);

	std::cout << (result ? "ok x64dll" : "fail x64dll") << std::endl;


__exit:
	if (hDevice != NULL)
	{
		CloseHandle(hDevice);
	}
	if (dllx64Ptr)
	{
		free(dllx64Ptr);
	}
	if (dllx86Ptr)
	{
		free(dllx86Ptr);
	}
	getchar();
	return 0;
}