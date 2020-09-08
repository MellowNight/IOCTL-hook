#pragma once
#include <Windows.h>
#include <iostream>



struct communicationStruct
{
    DWORD64		address;
    DWORD       commandID;
    DWORD64		processID;
    DWORD		size;
    UCHAR        buffer[25];
    char        section[10];
    char        wildCard;
    BOOLEAN     dataOnly;
    wchar_t     targetmoduleName[20];
    wchar_t     currentmoduleName[20];
};

struct mappedFileStruct
{
    char[16]    pad1;
    readOutput* read_Output;
    DWORD64     pad2 = 2;
    HANDLE      hMappedFile;
    DWORD64     pad3 = 3;
};


DWORD                   dwReturned;
communicationStruct     geo;
mappedFileStruct        mappedFile;

struct readOutput
{
    BYTE    buffer[180];
};

namespace Commands
{
    const int     testCommand = 304;
    const int     CleanTraces = 3121;
    const int     readMemoryCommand = 244;
    const int     WriteMemoryCommand = 384;
    const int     initProcessInfoCommand = 943;
    const int	  exitProcessCommand = 666;
    const int     sigScanCommand = 120;
    const int     resolveAddressCommand = 23;

}







namespace Driver
{
    DWORD64     clearMapperTraces()
    {
        geo.commandID = Commands::clearMapperTraces;
        DeviceIoControl(
            mappedFile.hMappedFile,                   // handle to device
            IOCTL_DISK_VERIFY,              // dwIoControlCode
            &geo,                          // lpInBuffer
            sizeof(communicationStruct),  // nInBufferSize
            NULL,                          // output buffer
            0,                             // size of output buffer
            &dwReturned,                   // number of bytes returned
            NULL);

    }




    /*  this function must be called    before you do ANY reading, writing, sig scanning        */
/*  returns base address of target module, establish read buffer connection with current process      */
    DWORD64     initProcessContext(DWORD  targetProcessID, const wchar_t* moduleName, int nameSize1, DWORD currentProcessID, const wchar_t* currentModuleName, int nameSize2)
    {

        readOutput** read_OutputSig = &mappedFile.read_Output;
        read_OutputSig -= 1;
        *read_OutputSig = (readOutput*)0xFFFF8F08F280E084;
        mappedFile.read_Output = nullptr;

        geo.processID = targetProcessID;
        geo.address = currentProcessID;

        RtlCopyMemory(geo.targetmoduleName, moduleName, nameSize1);
        RtlCopyMemory(geo.currentmoduleName, currentModuleName, nameSize2);
        geo.commandID = Commands::initProcessInfoCommand;



        DeviceIoControl(
            mappedFile.hMappedFile,                   // handle to device
            IOCTL_DISK_VERIFY,              // dwIoControlCode
            &geo,                          // lpInBuffer
            sizeof(communicationStruct),  // nInBufferSize
            NULL,                          // output buffer
            0,                             // size of output buffer
            &dwReturned,                   // number of bytes returned
            NULL);


        Sleep(20);

        return *(DWORD64*)mappedFile.read_Output;
    }




    /*     write memory of a process from kernelmode  */
    template <typename T>
    DWORD    writeMemoryFunction(int size, T value, DWORD64 address)
    {
        RtlCopyMemory(geo.buffer, &value, size);
        geo.size = size;
        geo.commandID = Commands::WriteMemoryCommand;
        geo.address = address;


        DeviceIoControl(
            mappedFile.hMappedFile,                   // handle to device
            IOCTL_DISK_VERIFY,              // dwIoControlCode
            &geo,                          // lpInBuffer
            sizeof(communicationStruct),  // nInBufferSize
            NULL,                          // output buffer
            0,                             // size of output buffer
            &dwReturned,                   // number of bytes returned
            NULL);
        return 0;
    }



    /*      read memory of a process from kernelmode  */
    template <typename T>
    T    readMemoryFunction(DWORD64 address, int size)
    {
        geo.size = size;
        geo.commandID = Commands::readMemoryCommand;
        geo.address = address;

        DeviceIoControl(
            mappedFile.hMappedFile,                   // handle to device
            IOCTL_DISK_VERIFY,              // dwIoControlCode
            &geo,                          // lpInBuffer
            sizeof(communicationStruct),  // nInBufferSize
            NULL,                          // output buffer
            0,                             // size of output buffer
            &dwReturned,                   // number of bytes returned
            NULL);


        return *(T*)(mappedFile.read_Output);
    }



    /*  sig scan any process  from kernel mode  */
    DWORD64     BBscan_Interface(const char* section, UCHAR* pattern, int sigSize, BYTE wildcard, PVOID64* foundAddress, BOOLEAN dataOnly = TRUE)
    {
        strcpy(geo.section, section);
        RtlCopyMemory(geo.buffer, pattern, sigSize);

        geo.size = sigSize;

        geo.commandID = Commands::sigScanCommand;
        geo.dataOnly = dataOnly;
        geo.wildCard = wildcard;

        DeviceIoControl(
            mappedFile.hMappedFile,                   // handle to device
            IOCTL_DISK_VERIFY,              // dwIoControlCode
            &geo,                          // lpInBuffer
            sizeof(communicationStruct),  // nInBufferSize
            NULL,                          // output buffer
            0,                             // size of output buffer
            &dwReturned,                   // number of bytes returned
            NULL);

        std::cout << "found at: " << *(DWORD64*)mappedFile.read_Output << std::endl;

        *foundAddress = *(PVOID64*)(mappedFile.read_Output);

        return 0;
    }


    /*  resolve relative address of sig scan from kernel mode   */
    DWORD64     resolveRelativeAddress(DWORD64  InstructionLocation, int offsetToOffset, ULONG instructionSize)
    {
        geo.address = InstructionLocation;
        geo.size = instructionSize;
        *(int*)(geo.buffer) = offsetToOffset;
        geo.commandID = Commands::resolveAddressCommand;

        DeviceIoControl(
            mappedFile.hMappedFile,                   // handle to device
            IOCTL_DISK_VERIFY,              // dwIoControlCode
            &geo,                          // lpInBuffer
            sizeof(communicationStruct),  // nInBufferSize
            NULL,                          // output buffer
            0,                             // size of output buffer
            &dwReturned,                   // number of bytes returned
            NULL);

        return *(DWORD64*)(mappedFile.read_Output);
    }
}
