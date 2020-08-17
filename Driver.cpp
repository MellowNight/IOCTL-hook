#include "KernelUtils.h"
#include "kdmapperTraces.h"
#include "commandsOffsets.h"




DWORD64 initProcess(HANDLE processID, HANDLE clientProcessID, communicationStruct* systemBuffer)	/*		setup required info	(and sig scan), find read output buffer		*/
{
	PsLookupProcessByProcessId(processID, &TargetProcess);
	PsLookupProcessByProcessId(clientProcessID, &clientProcess);


	//	get address of output buffer
	BOOLEAN isWow64 = (PsGetProcessWow64Process(TargetProcess) != NULL) ? TRUE : FALSE;
	UNICODE_STRING clientprocessName;
	RtlInitUnicodeString(&clientprocessName, systemBuffer->currentmoduleName);

	DWORD64		gameBaseAddress = 0;
	BOOLEAN isclientWow64 = (PsGetProcessWow64Process(clientProcess) != NULL) ? TRUE : FALSE;
	UNICODE_STRING processName;

	RtlInitUnicodeString(&processName, systemBuffer->targetmoduleName);


	KAPC_STATE apc;
	KeStackAttachProcess(TargetProcess, &apc);


	gameBaseAddress	 =	(ULONG64)GetUserModule(TargetProcess, &processName, isWow64);
	GameBaseAddress = gameBaseAddress;


	KeUnstackDetachProcess(&apc);

	if (gameBaseAddress == 0)
	{
		gameBaseAddress = 0x400000;
	}

	KeStackAttachProcess(clientProcess, &apc);


	DWORD64		clientBaseAddress = (ULONG64)GetUserModule(clientProcess, &clientprocessName, isclientWow64); //BSOD problem line

	ClientBaseAddress = clientBaseAddress;

	UCHAR	pattern[] = { 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4 };
	UINT64	realPattern = 0xFFFF8F08F280E084;
	RtlCopyMemory(pattern, (PVOID64)&realPattern, sizeof(UINT64));
	BBScanSection(".data", pattern, 0xCC, sizeof(UINT64), reinterpret_cast<PVOID64*>(&readOutputAddress), (PVOID64)ClientBaseAddress, TRUE);

	readOutputAddress += 8;
	
	RtlCopyMemory(&readOutputAddress, (PVOID64)readOutputAddress, sizeof(DWORD64));

	DbgPrint("initProcess(): Buffer Address is: %p \n", readOutputAddress);

	RtlCopyMemory((PVOID64)readOutputAddress, &GameBaseAddress, sizeof(GameBaseAddress));


	KeUnstackDetachProcess(&apc);

	ClientBaseAddress = clientBaseAddress;

	DbgPrint("reached 1 \n");

	return gameBaseAddress;
}

void exitProcessFunction()
{
	if (clientProcess)
	{
		ObDereferenceObject(clientProcess);
	}
	if (TargetProcess)
	{
		ObDereferenceObject(TargetProcess);
	}
}


void EVERYTHINGhandler(communicationStruct* SystemBuffer)
{
	SystemBuffer = (communicationStruct*)(((PIRP)interceptedIRP)->AssociatedIrp.SystemBuffer);

	DWORD64 result;
	KFLOATING_SAVE     saveData;
	KAPC_STATE	apcState;
	KeSaveFloatingPointState(&saveData);
	switch (SystemBuffer->commandID)
	{
	case	CleanTraces:
		clearKdmapperTraces();			/*	clear traces	*/
		break;
	case	ReadMemoryCommand:
		ReadMemory(SystemBuffer->address, (PVOID)&SystemBuffer->buffer, SystemBuffer->size, TargetProcess, clientProcess, (PVOID)readOutputAddress);		/*	Read memory		*/
		break;
	case	 WriteMemorycommand:
		WriteMemory(SystemBuffer->address, (PVOID)&SystemBuffer->buffer, SystemBuffer->size, TargetProcess);	/*	Write memory	*/
		break;
	case	initProcessInfoCommand:
		GameBaseAddress = initProcess((HANDLE)SystemBuffer->processID, (HANDLE)SystemBuffer->address, SystemBuffer);
		break;			/*		setup required info	(and sig scan)	*/
	case	sigScanCommand:

		KeStackAttachProcess(TargetProcess, &apcState);
		BBScanSection(SystemBuffer->section, SystemBuffer->buffer, SystemBuffer->wildCard, SystemBuffer->size,
			(PVOID64*)&SystemBuffer->address, (PVOID64)GameBaseAddress, SystemBuffer->dataOnly);
		KeUnstackDetachProcess(&apcState);

		WriteMemory(readOutputAddress, &SystemBuffer->address, sizeof(DWORD64), clientProcess);
		break;
	case	 resolveAddressCommand:
		KeStackAttachProcess(TargetProcess, &apcState);
		result = (DWORD64)ResolveRelativeAddress((PVOID)SystemBuffer->address, *(int*)(SystemBuffer->buffer), SystemBuffer->size);
		KeUnstackDetachProcess(&apcState);
		WriteMemory(readOutputAddress, &result, sizeof(DWORD64), clientProcess);
		break;
	case	testCommand:
		DbgPrint("test command called\n");
		break;
	case	 exitProcess:
		exitProcessFunction();
		break;
	default:
		break;
	}

	KeRestoreFloatingPointState(&saveData);
	return;
}


#pragma optimize("", off)
// handles EVERY COMMAND
void EVERYTHING()
{

	// here we get command from IRP system buffer (RSI)
	int a1 = 5;
	int a2 = 5;
	int a3 = 5;		// 32 free bytes
	int a4 = 5;

	EVERYTHINGhandler(SystemBuffer);

	// hook my own function like a moron because microsoft wont let me use inline asm
	// padding for the shellcode
	int a5 = 5;
	int a6 = 5;		// 32 free bytes
	int a7 = 5;		
	int a8 = 5;
	DbgPrint("EVERYTHING failed to return\n");
}
#pragma optimize("", on)






// hook my own function like a moron because microsoft wont let me use inline asm
BOOLEAN PlaceEverythingHook()
{
	ULONG		diskSysSize;
	PVOID		diskSysBase	 =		getDiskSysBase(&diskSysSize);

	ULONG64		returnPlaceOfIOCTL	 =	 (ULONG64)diskSysBase + 0x16AF;	//112E for 1903/1909

	//grab values from rsi and r14 (device object and pirp)

	ULONG64		handlerPointer = (ULONG64)(PVOID64)EVERYTHING;
	handlerPointer += 48;	 //skip past dbgprint

	UCHAR		shellCode[]	 =	 "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0";

	ULONG64		jumpAddress	 =	 (ULONG64)(PVOID64)returnPlaceOfIOCTL;

	memcpy(shellCode + 2, &jumpAddress, 8); // copy address into shellcode






	/*
	get value from r14 and pop into interceptedIRP variable
	14 bytes required

	41 56									push r14
	48 b8 00 00 00 00 00 00 00 00			mov rax, &interceptedIRP
	8f 00  									pop[rax]
	*/


	UCHAR		shellCodeForR14[]	=	"\x56\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x8f\x00\x90\x90";
	PVOID64 iinterceptedIRP = &interceptedIRP;
	memcpy(shellCodeForR14 + 3, (PVOID64)(&iinterceptedIRP), 8);	//has to be 3 if its push rsi

	DbgPrint("address of intercepted IRP pointer is: %p \n", (ULONG64)&interceptedIRP);

	if (MmIsAddressValid((PVOID)handlerPointer) && MmIsAddressValid((PVOID)(handlerPointer + sizeof(shellCode) - 1)))
	{
		KIRQL   tempirql = KeRaiseIrqlToDpcLevel();

		ULONG64  cr0 = __readcr0();

		cr0 &= 0xfffffffffffeffff;

		__writecr0(cr0);

		_disable();

		RtlCopyMemory((PVOID)handlerPointer, shellCode, 12);

		handlerPointer = (ULONG64)(PVOID64)EVERYTHING;

		handlerPointer += 21; // should be 20 if it is push r14, 21 if its push rsi

		RtlCopyMemory((PVOID)handlerPointer, shellCodeForR14, sizeof(shellCodeForR14) - 1);
		cr0 = __readcr0();

		cr0 |= 0x10000;

		_enable();

		__writecr0(cr0);

		KeLowerIrql(tempirql);
	}
	return TRUE;


}



BOOLEAN PlaceDiskHook()
{
	// Setup all the required info

	ULONG		diskSysSize;
	PVOID		diskSysBase = getDiskSysBase(&diskSysSize);



	//DiskIoctlVerify
	ULONG64		hookLocation = (ULONG64)diskSysBase + 0x32A2;	//2D90 for 1903 and 1909


	//  "\x48\xB8"  EVERYTHING address "\xFF\xE0";   
	//mov rax, EVERYTHING
	//jmp rax


	BYTE		shellCode[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

	ULONG64		jumpAddress = (ULONG64)(PVOID64)EVERYTHING;
	jumpAddress += 21; // skip sub rsp and padding (should be 20 if you push r14 instead)

	memcpy(shellCode + 2, &jumpAddress, 8);



	//for now we will write without using write function because we don't want to attach to any process

	if (MmIsAddressValid((PVOID)hookLocation) && MmIsAddressValid((PVOID)(hookLocation + sizeof(shellCode) - 1)))
	{
		KIRQL   tempirql = KeRaiseIrqlToDpcLevel();

		ULONG64  cr0 = __readcr0();

		cr0 &= 0xfffffffffffeffff;

		__writecr0(cr0);

		_disable();

		RtlCopyMemory((PVOID64)hookLocation, shellCode, 12);

		cr0 = __readcr0();

		cr0 |= 0x10000;

		_enable();

		__writecr0(cr0);

		KeLowerIrql(tempirql);
	}
	return TRUE;

}



/*
							  loc_2D90:
48 8B D6                      mov     rdx, rsi
49 8B CE                      mov     rcx, r14        ; DeviceObject
E8 C9 15 00 00                call    DiskIoctlVerify
90                            nop
E9 8D E3 FF FF                jmp     loc_112E
*/

extern "C"
NTSTATUS DriverEntry(_In_ _DRIVER_OBJECT * DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	ULONG sizeOfModule;
	PlaceDiskHook();
	PlaceEverythingHook();
	return Status;
}



NTSTATUS DriverA(_In_ _DRIVER_OBJECT* DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	DbgPrint("driver start \n");
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN ClearStatus;


	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverEntry(NULL, NULL);
	return Status;
}
