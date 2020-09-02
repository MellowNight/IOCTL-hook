#pragma once
#include "KernelUtils.h"
#include "kdmapperTraces.h"
#include "Globals.h"


void	hookedIoctl();



void	placeJMP(ULONG64	addr, ULONG64	jmpAddr, BYTE* oldBytes)
{
	KIRQL	tempIRQL = Utils::disableWP();

	if (oldBytes != NULL)
	{
		memcpy(oldBytes, (PVOID64)addr, 12);
	}

	memcpy(Shellcode::JmpRax + 2, &jmpAddr, 8);

	memcpy((PVOID64)addr, Shellcode::JmpRax, 12);

	Utils::enableWP(tempIRQL);

	return;
}


void	grabR14(ULONG64	shellcodeAddr, ULONG64	outBuffer, BYTE* oldBytes)
{
	KIRQL	tempIRQL = Utils::disableWP();

	if (oldBytes != NULL)
	{
		memcpy(oldBytes, (PVOID64)shellcodeAddr, 15);
	}

	memcpy(Shellcode::grabR14 + 3, &outBuffer, 8);

	memcpy((PVOID64)shellcodeAddr, Shellcode::grabR14, 12);

	Utils::enableWP(tempIRQL);

	return;
}


/*

what this does:

1. places code in hooked ioctl to intercept IRP system buffer (in register R14)
2. places code in hooked ioctl to jump back to IoctlDiskVerify() in disk.sys

*/
BOOLEAN PlaceMyHook()
{
	ULONG		diskSysSize;
	PVOID		diskSysBase = Utils::getDriverBaseAddress(&diskSysSize, "disk.sys");

	ULONG64		exit = (ULONG64)diskSysBase + HookOffsets::exit1909;

	ULONG64		hookedioctl = (ULONG64)(PVOID64)hookedIoctl;



	/*
	get value from r14 and pop into interceptedIRP variable
	14 bytes required

	41 56									push r14
	48 b8 00 00 00 00 00 00 00 00			mov rax, &interceptedIRP
	8f 00  									pop[rax]
	*/




	hookedioctl += 48;

	placeJMP(hookedioctl, exit, NULL);

	hookedioctl = (ULONG64)(PVOID64)hookedIoctl;

	hookedioctl += 21;			// these magic numbers are offsets from hookedioctl() function

	PVOID64 iinterceptedIRP = &Globals::interceptedIRP;

	grabR14(hookedioctl, (ULONG64)iinterceptedIRP, NULL);



	return TRUE;
}



BOOLEAN PlaceDiskHook()
{
	ULONG		diskSysSize;
	PVOID		diskSysBase = Utils::getDriverBaseAddress(&diskSysSize, "disk.sys");



	ULONG64		hookLocation = (ULONG64)diskSysBase + HookOffsets::hook1909;

	ULONG64		jumpAddress = (ULONG64)(PVOID64)hookedIoctl;
	jumpAddress += 21;

	placeJMP(hookLocation, jumpAddress, NULL);


	return TRUE;
}

