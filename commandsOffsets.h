#pragma once
#include "Undocumented.h"




struct communicationStruct
{
    DWORD64	        	address;
    DWORD               commandID;
    DWORD64	            processID;
    DWORD	            size;
    const UCHAR         buffer[25];
    char                section[10];
    char                wildCard;
    wchar_t             targetmoduleName[20];
    wchar_t             currentmoduleName[20];
};






namespace   Globals
{
    ULONG64		             interceptedIRP = 0;
    communicationStruct*     SystemBuffer = 0;
    PEPROCESS		         TargetProcess = 0;
    DWORD64			         ClientBaseAddress = 0;
    DWORD64			         GameBaseAddress = 0;
    static DWORD64	         readOutputAddress = 0; // for sending data to usermode
    PEPROCESS		         clientProcess = 0;

} 


enum    COMMAND : int
{
    sigScanCommand = 120,
    CleanTraces = 3121,
    ReadMemoryCommand = 244,
    WriteMemorycommand = 384,
    initProcessInfoCommand = 943,
    exitProcess = 666,
    resolveAddressCommand = 23,
    testCommand = 304,
};


namespace HookOffsets
{
    DWORD64     hook1903 = 0x2D90;   /*     hook location    */
    DWORD64     exit1903 = 0x112E;   /*     return location     */

    DWORD64     hook1909 = 0x2D90; 
    DWORD64     exit1909 = 0x112E; 

    DWORD64     hook2004 = 0x32A2;  
    DWORD64     hook2004 = 0x16AF;  
}