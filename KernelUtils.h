#pragma once


#pragma once
#include "Undocumented.h"
#include <intrin.h>




#define MM_UNLOADED_DRIVERS_SIZE 50
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ
#define STANDARD_RIGHTS_ALL 0x001F0000L





ULONG KernelSize;
PVOID KernelBase;
PVOID getKernelBase(OUT PULONG pSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Bytes = 0;
	PRTL_PROCESS_MODULES arrayOfModules;
	PVOID routinePtr = NULL; /*RoutinePtr points to a
	routine and checks if it is in Ntoskrnl*/

	UNICODE_STRING routineName;

	if (KernelBase != NULL)
	{
		if (pSize)
			*pSize = KernelSize;
		return KernelBase;
	}

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");
	routinePtr = MmGetSystemRoutineAddress(&routineName); //get address of NtOpenFile


	if (routinePtr == NULL)
	{
		return NULL;
	}
	else
	{

		DbgPrint("MmGetSystemRoutineAddress inside getkernelbase succeed\n");
	}


	//get size of system module information
	Status = ZwQuerySystemInformation(SystemModuleInformation, 0, Bytes, &Bytes);
	if (Bytes == 0)
	{
		DbgPrint("%s: Invalid SystemModuleInformation size\n");
		return NULL;
	}


	arrayOfModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x454E4F45); //array of loaded kernel modules
	RtlZeroMemory(arrayOfModules, Bytes); //clean memory


	Status = ZwQuerySystemInformation(SystemModuleInformation, arrayOfModules, Bytes, &Bytes);
	if (NT_SUCCESS(Status))
	{
		DbgPrint("ZwQuerySystemInformation inside getkernelbase succeed\n");
		PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
		for (int i = 0; i < arrayOfModules->NumberOfModules; ++i)
		{

			if (routinePtr >= pMod[i].ImageBase && routinePtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{

				KernelBase = pMod[i].ImageBase;
				KernelSize = pMod[i].ImageSize;

				if (pSize)
					*pSize = KernelSize;
				break;
			}
		}
	}
	if (arrayOfModules)
		ExFreePoolWithTag(arrayOfModules, 0x454E4F45); // 'ENON'

	DbgPrint("KernelSize : %i\n", KernelSize);
	DbgPrint("g_KernelBase : %p\n", KernelBase);
	return (PVOID)KernelBase;
}




PVOID getDiskSysBase(OUT PULONG pSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Bytes = 0;
	PRTL_PROCESS_MODULES arrayOfModules;



	PVOID			diskSysBase = 0;
	ULONG64			DiskSysSize = 0;



	//get size of system module information
	Status = ZwQuerySystemInformation(SystemModuleInformation, 0, Bytes, &Bytes);
	if (Bytes == 0)
	{
		DbgPrint("%s: Invalid SystemModuleInformation size\n");
		return NULL;
	}


	arrayOfModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0x45454545); //array of loaded kernel modules
	RtlZeroMemory(arrayOfModules, Bytes); //clean memory


	Status = ZwQuerySystemInformation(SystemModuleInformation, arrayOfModules, Bytes, &Bytes);

	if (NT_SUCCESS(Status))
	{
		DbgPrint("ZwQuerySystemInformation inside getkernelbase succeed\n");
		PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
		for (int i = 0; i < arrayOfModules->NumberOfModules; ++i)
		{
			//list the module names:

			DbgPrint("Image name: %s\n", pMod[i].FullPathName + pMod[i].OffsetToFileName); 
			// path name plus some amount of characters will lead to the name itself
			const char* DriverName = (const char*)pMod[i].FullPathName + pMod[i].OffsetToFileName;

			if (strcmp(DriverName, "disk.sys") == 0)
			{
				DbgPrint("found disk.sys\n");


				diskSysBase = pMod[i].ImageBase;
				DiskSysSize = pMod[i].ImageSize;

				DbgPrint("Disk.sys Size : %i\n", DiskSysSize);
				DbgPrint("Disk.sys Base : %p\n", diskSysBase);


				if (arrayOfModules)
					ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'




				*pSize = DiskSysSize;
				return diskSysBase;
			}
		}
	}
	if (arrayOfModules)
		ExFreePoolWithTag(arrayOfModules, 0x45454545); // 'ENON'



	*pSize = DiskSysSize;
	return (PVOID)diskSysBase;
}





NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}



NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr, BOOLEAN dataOnly = FALSE)
{

	//ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

	if (nullptr == base)
		base = getKernelBase(NULL);
	if (base == nullptr)
		return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

	//PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	PVOID ptr = NULL;

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{

		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if ((dataOnly == FALSE) && ((RtlCompareString(&s1, &s2, TRUE) == 0) || (pSection->Characteristics & IMAGE_SCN_CNT_CODE) || (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)))
		{

			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
				DbgPrint("found\r\n");
				return status;
			}
			//we continue scanning because there can be multiple sections with the same name.
		}
		else if ((dataOnly == TRUE) && (RtlCompareString(&s1, &s2, TRUE) == 0))
		{
			DbgPrint("valid section\r\n");
			ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
				DbgPrint("BBscansection(): found at address: %p ", *(PULONG64)ppFound);
				return status;
			}
			return status;
			//we continue scanning because there can be multiple sections with the same name.
		}
	}

	return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
}

PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}





PVOID GetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
{
	ASSERT(pProcess != NULL);
	if (pProcess == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		LARGE_INTEGER time = { 0 };
		time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

		// Wow64 process
		if (isWow64)
		{
			PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
			if (pPeb32 == NULL)
			{
				return NULL;
			}

			// Wait for loader a bit
			for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
			{
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb32->Ldr)
			{
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
				pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
				pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
			{
				UNICODE_STRING ustr;
				PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

				if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
					return (PVOID)pEntry->DllBase;
			}
		}
		// Native process
		else
		{
			PPEB pPeb = PsGetProcessPeb(pProcess);
			if (!pPeb)
			{
				return NULL;
			}

			// Wait for loader a bit
			for (INT i = 0; !pPeb->Ldr && i < 10; i++)
			{
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb->Ldr)
			{
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
				pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
				pListEntry = pListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
					return pEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return NULL;
}



HANDLE	GetProcessPID(const wchar_t* NameOfProcess)
{
	auto				Status = STATUS_SUCCESS;
	UNICODE_STRING		ClientName = { 0 };
	HANDLE				processID = nullptr;
	PVOID				SystemProcessInfo = nullptr;
	DWORD				buffer_size = NULL;



	RtlInitUnicodeString(&ClientName, L"UserModeClient.exe");
	Status = ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, 0, &buffer_size);
	while (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (SystemProcessInfo)	ExFreePool(SystemProcessInfo);
		SystemProcessInfo = ExAllocatePool(NonPagedPool, buffer_size);
		Status = ZwQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, buffer_size, &buffer_size);
	}
	auto	ProcessInformation = static_cast<PSYSTEM_PROCESS_INFORMATION>(SystemProcessInfo);
	for (;;)
	{

		if (FsRtlIsNameInExpression(&ClientName, &(ProcessInformation->ImageName), FALSE, NULL) == TRUE)
		{
			processID = ProcessInformation->ProcessId;
			break;
		}

		if (ProcessInformation->NextEntryOffset == 0)
		{
			break;
		}
		ProcessInformation = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)ProcessInformation) + ProcessInformation->NextEntryOffset);
	}
	ExFreePool(SystemProcessInfo);
	return processID;

}


struct readOutput
{
	BYTE buffer[240];
};




VOID	ReadMemory(ULONG64 address, PVOID buffer, SIZE_T size, PEPROCESS process, PEPROCESS clientProcess, PVOID readBufferAddress)
{	
	{
		KAPC_STATE  apc_state;
		KeStackAttachProcess(process, &apc_state);

		if (MmIsAddressValid((PVOID64)address) && MmIsAddressValid((PVOID64)(address + size)))
		{
			RtlCopyMemory(buffer, (PVOID64)address, size);
		}

		KeUnstackDetachProcess(&apc_state);
	}


	KAPC_STATE	apc_state;
	KeStackAttachProcess(clientProcess, &apc_state);
	if (MmIsAddressValid((PVOID)readBufferAddress))
	{

		KIRQL   tempirql = KeRaiseIrqlToDpcLevel();

		ULONG64  cr0 = __readcr0();

		cr0 &= 0xfffffffffffeffff;
		__writecr0(cr0);

		_disable();

		RtlCopyMemory(readBufferAddress, buffer, size);


		cr0 = __readcr0();

		cr0 |= 0x10000;

		_enable();

		__writecr0(cr0);

		KeLowerIrql(tempirql);
	}
	else
	{
		DbgPrint("address invalid!!! tried to read memory at: %p \n", readBufferAddress);
	}

	KeUnstackDetachProcess(&apc_state);

}



VOID	WriteMemory(ULONG64 address, PVOID buffer, SIZE_T size, PEPROCESS process)
{
	
	KAPC_STATE  apc_state;
	KeStackAttachProcess(process, &apc_state);
	if (MmIsAddressValid((PVOID)address) && MmIsAddressValid((PVOID)(address + size)))
	{
		KIRQL   tempirql = KeRaiseIrqlToDpcLevel();

		ULONG64  cr0 = __readcr0();

		cr0 &= 0xfffffffffffeffff;
		__writecr0(cr0);

		_disable();

		RtlCopyMemory((PVOID64)address, buffer, size);

		cr0 = __readcr0();

		cr0 |= 0x10000;

		_enable();

		__writecr0(cr0);

		KeLowerIrql(tempirql);
	}
	KeUnstackDetachProcess(&apc_state);

}



