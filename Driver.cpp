#include "placeHooks.h"




/*		setup required info	(and sig scan for read output buffer)		*/


DWORD64 initialize(HANDLE processID, HANDLE clientProcessID, communicationStruct* systemBuffer)	
{
	/*	our driver client process	*/

	PsLookupProcessByProcessId(clientProcessID, &Globals::clientProcess);

	UNICODE_STRING		clientprocessName;

	RtlInitUnicodeString(&clientprocessName, systemBuffer->currentmoduleName);

	BOOLEAN				isclientWow64 = (PsGetProcessWow64Process(Globals::clientProcess) != NULL) ? TRUE : FALSE;

	DWORD64				clientBaseAddress = (ULONG64)GetUserModule(Globals::clientProcess, &clientprocessName, isclientWow64); 

	Globals::ClientBaseAddress = clientBaseAddress;



	/*	game process	*/

	PsLookupProcessByProcessId(processID, &Globals::TargetProcess);

	UNICODE_STRING		processName;

	RtlInitUnicodeString(&processName, systemBuffer->targetmoduleName);

	BOOLEAN				isWow64 = (PsGetProcessWow64Process(Globals::TargetProcess) != NULL) ? TRUE : FALSE;

	DWORD64				gameBaseAddress = 0;




	KAPC_STATE apc;
	KeStackAttachProcess(Globals::TargetProcess, &apc);

	gameBaseAddress	 =	(ULONG64)GetUserModule(Globals::TargetProcess, &processName, isWow64);

	Globals::GameBaseAddress = gameBaseAddress;

	KeUnstackDetachProcess(&apc);

	if (gameBaseAddress == 0)
	{
		gameBaseAddress = 0x400000;
	}





	/*	now get the base address of our own usermode		*/

	KeStackAttachProcess(Globals::clientProcess, &apc);



	/*	sig scan for our communication buffer (kernel -> user communication)	*/

	UCHAR	pattern[8];

	UINT64	realPattern = 0xFFFF8F08F280E084;

	RtlCopyMemory(pattern, (PVOID64)&realPattern, sizeof(UINT64));


	BBScanSection(".data", pattern, 0xCC, sizeof(UINT64), (PVOID64*)(&Globals::readOutputAddress), (PVOID64)Globals::ClientBaseAddress);


	Globals::readOutputAddress += 8;

	Globals::readOutputAddress = *(DWORD64*)Globals::readOutputAddress;
	

	DbgPrint("initialize(): Buffer Address is: %p \n", Globals::readOutputAddress);

	RtlCopyMemory((PVOID64)Globals::readOutputAddress, &Globals::GameBaseAddress, sizeof(Globals::GameBaseAddress));



	KeUnstackDetachProcess(&apc);




	Globals::ClientBaseAddress = clientBaseAddress;


	return gameBaseAddress;
}


/*	called when the hack stops "using" the game and the driver		*/

void exitProcessFunction()
{
	if (Globals::clientProcess)
	{
		ObDereferenceObject(Globals::clientProcess);
	}
	if (Globals::TargetProcess)
	{
		ObDereferenceObject(Globals::TargetProcess);
	}
}



void	hookedIoctlhandler(communicationStruct* SystemBuffer)
{
	SystemBuffer = (communicationStruct*)(((PIRP)Globals::interceptedIRP)->AssociatedIrp.SystemBuffer);

	DWORD64 result;
	KFLOATING_SAVE     saveData;
	KAPC_STATE	apcState;
	KeSaveFloatingPointState(&saveData);


	switch (SystemBuffer->commandID)
	{
	case	CleanTraces:

		/*	clear traces	*/

		clearKdmapperTraces();			
		break;

	case	ReadMemoryCommand:

		/*	Read memory		*/

		ReadMemory(SystemBuffer->address, (PVOID)&SystemBuffer->buffer, SystemBuffer->size,
			Globals::TargetProcess, Globals::clientProcess, (PVOID)Globals::readOutputAddress);		
		break;

	case	 WriteMemorycommand:

		/*	Write memory	*/

		WriteMemory(SystemBuffer->address, (PVOID)&SystemBuffer->buffer, SystemBuffer->size, Globals::TargetProcess);	
		break;

	case	initProcessInfoCommand:

		Globals::GameBaseAddress = initialize((HANDLE)SystemBuffer->processID, (HANDLE)SystemBuffer->address, SystemBuffer);
		break;			

	case	sigScanCommand:

		KeStackAttachProcess(Globals::TargetProcess, &apcState);
		BBScanSection(SystemBuffer->section, SystemBuffer->buffer, SystemBuffer->wildCard, SystemBuffer->size,
			(PVOID64*)&SystemBuffer->address, (PVOID64)Globals::GameBaseAddress);
		KeUnstackDetachProcess(&apcState);

		WriteMemory(Globals::readOutputAddress, &SystemBuffer->address, sizeof(DWORD64), Globals::clientProcess);

		break;



	case	 resolveAddressCommand:

		/*	for resolving relative address (sig scanning)	*/

		KeStackAttachProcess(Globals::TargetProcess, &apcState);

		result = (DWORD64)ResolveRelativeAddress((PVOID)SystemBuffer->address, *(int*)(SystemBuffer->buffer), SystemBuffer->size);

		KeUnstackDetachProcess(&apcState);

		WriteMemory(Globals::readOutputAddress, &result, sizeof(DWORD64), Globals::clientProcess);

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
void	hookedIoctl()
{
	/* padding for the shellcode
	here we get info from IRP system buffer (RSI)	*/

	int a1 = 1;
	int a2 = 1;
	int a3 = 1;		// 32 free bytes
	int a4 = 1;

	hookedIoctlhandler(Globals::SystemBuffer);

	// hook my own function like a moron because microsoft wont let me use inline asm

	int a5 = 1;
	int a6 = 1;		// 32 free bytes
	int a7 = 1;		
	int a8 = 1;
}
#pragma optimize("", on)









extern "C"
NTSTATUS DriverEntry(_In_ _DRIVER_OBJECT * DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);


	PlaceDiskHook();

	PlaceMyHook();

	return Status;
}



NTSTATUS DriverA(_In_ _DRIVER_OBJECT* DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	DbgPrint("driver start \n");
	NTSTATUS Status = STATUS_SUCCESS;


	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverEntry(NULL, NULL);
	return Status;
}
