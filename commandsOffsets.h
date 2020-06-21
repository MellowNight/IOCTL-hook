#pragma once
#include "Undocumented.h"




struct communicationStruct
{
    DWORD64		address;
    DWORD       commandID;
    DWORD64		processID;
    DWORD		size;
    const UCHAR        buffer[25];
    char        section[10];
    char        wildCard;
    BOOLEAN     dataOnly;
    wchar_t     targetmoduleName[20];
    wchar_t     currentmoduleName[20];
};



/*		super important info!!!!		*/
ULONG64		interceptedIRP = (ULONG64)0x5555;
communicationStruct* SystemBuffer;
PEPROCESS		TargetProcess;
DWORD64			ClientBaseAddress = 0;
DWORD64			GameBaseAddress = 0;
static DWORD64	readOutputAddress; // for sending data to usermode
PEPROCESS		clientProcess;

const int     sigScanCommand = 120;
const int     CleanTraces = 3121;
const int     ReadMemoryCommand = 244;
const int     WriteMemorycommand = 384;
const int     initProcessInfoCommand = 943;
const int	  exitProcess = 666;
const int     resolveAddressCommand = 23;
const int     testCommand = 304;