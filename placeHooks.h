#pragma once
#include "KernelUtils.h"
#include "kdmapperTraces.h"
#include "commandsOffsets.h"


/*

what this does:

1. places code in hooked ioctl to intercept IRP system buffer
2. places code in hooked ioctl to jump back to IoctlDiskVerify() in disk.sys

*/
BOOLEAN PlaceMyHook()
{
	ULONG		diskSysSize;
	PVOID		diskSysBase = getDriverBaseAddress(&diskSysSize, "disk.sys");

	ULONG64		returnPlaceOfIOCTL = (ULONG64)diskSysBase + HookOffsets::exit1909;

	//grab values from rsi and r14 (device object and pirp)

	ULONG64		functionPointer = (ULONG64)(PVOID64)hookedIoctl;

	functionPointer += 48;	 /*		skip past all the code	instructions		*/

	UCHAR		shellCode[] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0";

	ULONG64		jumpAddress = (ULONG64)(PVOID64)returnPlaceOfIOCTL;

	memcpy(shellCode + 2, &jumpAddress, 8);






	/*
	get value from r14 and pop into interceptedIRP variable
	14 bytes required

	41 56									push r14
	48 b8 00 00 00 00 00 00 00 00			mov rax, &interceptedIRP
	8f 00  									pop[rax]
	*/


	UCHAR		shellCodeForR14[] = "\x56\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x8f\x00\x90\x90";

	PVOID64 iinterceptedIRP = &Globals::interceptedIRP;
	memcpy(shellCodeForR14 + 3, (PVOID64)(&iinterceptedIRP), 8);


	DbgPrint("address of intercepted IRP pointer is: %p \n", (ULONG64)&Globals::interceptedIRP);

	if (MmIsAddressValid((PVOID)functionPointer) && MmIsAddressValid((PVOID)(functionPointer + sizeof(shellCode) - 1)))
	{
		KIRQL   tempirql = KeRaiseIrqlToDpcLevel();

		ULONG64  cr0 = __readcr0();

		cr0 &= 0xfffffffffffeffff;

		__writecr0(cr0);

		_disable();

		RtlCopyMemory((PVOID)functionPointer, shellCode, 12);

		functionPointer = (ULONG64)(PVOID64)hookedIoctl;

		functionPointer += 21; // should be 20 if it is push r14, 21 if its push rsi

		RtlCopyMemory((PVOID)functionPointer, shellCodeForR14, sizeof(shellCodeForR14) - 1);
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
	ULONG		diskSysSize;
	PVOID		diskSysBase = getDriverBaseAddress(&diskSysSize, "disk.sys");



	ULONG64		hookLocation = (ULONG64)diskSysBase + HookOffsets::hook1909;




	BYTE		shellCode[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

	ULONG64		jumpAddress = (ULONG64)(PVOID64)hookedIoctl;
	jumpAddress += 21;

	memcpy(shellCode + 2, &jumpAddress, 8);




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

