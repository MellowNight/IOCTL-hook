#pragma once

#include "KernelUtils.h"

BOOLEAN IsUnloadedDriverEntryEmpty(
	_In_ PMM_UNLOADED_DRIVER Entry
)
{
	if (Entry->Name.MaximumLength == 0 ||
		Entry->Name.Length == 0 ||
		Entry->Name.Buffer == NULL)
	{
		return TRUE;
	}

	return FALSE;
}

UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
UNICODE_STRING NewDriverName = RTL_CONSTANT_STRING(L"ddlpqgz.sys");


PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG				MmLastUnloadedDriver;
UCHAR MmUnloadedDriverSig[] = "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74";

NTSTATUS findMMunloadedDrivers()
{
	PVOID MmUnloadedDriversPtr = NULL;

	NTSTATUS status = BBScanSection("PAGE", MmUnloadedDriverSig, 0x00, sizeof(MmUnloadedDriverSig) - 1, (PVOID*)(&MmUnloadedDriversPtr));
	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to find MmUnloadedDriver sig %p\n", MmUnloadedDriversPtr);
		return FALSE;
	}
	DbgPrint("MmUnloadedDriversPtr address found: %p  \n", MmUnloadedDriversPtr);


	MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(MmUnloadedDriversPtr, 3, 7);
	//REAL REAL mmunloadeddrivers
	DbgPrint("MmUnloadedDrivers real location is: %p\n", &MmUnloadedDrivers);

	return status;
}






UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C";
UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";

bool LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	PVOID PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;
	if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBLockPtr_sig, 0, sizeof(PiDDBLockPtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
		DbgPrint("Unable to find PiDDBLockPtr sig. Piddblockptr is: %p.\n", PiDDBLockPtr);
		return false;
	}
	DbgPrint("found PiDDBLockPtr sig. Piddblockptr is: %p\n", PiDDBLockPtr);

	if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr)))) {
		DbgPrint("Unable to find PiDDBCacheTablePtr sig. PiDDBCacheTablePtr is: %p\n", PiDDBCacheTablePtr);
		return false;
	}
	DbgPrint("found PiDDBCacheTablePtr sig. PiDDBCacheTablePtr is: %p\n", PiDDBCacheTablePtr);


	PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

	*lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return true;
}





BOOLEAN ClearPiddbCacheTable()
{
	PERESOURCE PiDDBLock = NULL;
	PRTL_AVL_TABLE PiDDBCacheTable = NULL;
	NTSTATUS Status = LocatePiDDB(&PiDDBLock, &PiDDBCacheTable);
	if (PiDDBCacheTable == NULL || PiDDBLock == NULL)
	{
		DbgPrint("LocatePIDDB lock and/or cachetable not found\n");
		return Status;
	}
	else
	{
		DbgPrint("Successfully found PiddbCachetable and lock!!!1111\n");
		DbgPrint("PiddbLock: %p\n", PiDDBLock);
		DbgPrint("PiddbCacheTable: %p\n", PiDDBCacheTable);

		PIDCacheobj Entry;
		UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
		Entry.DriverName = DriverName;
		Entry.TimeDateStamp = 0x5284EAC3;
		ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
		PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &Entry);

		if (pFoundEntry == NULL)
		{
			DbgPrint("pFoundEntry not found !!!\n");
			// release ddb resource lock
			ExReleaseResourceLite(PiDDBLock);
			return FALSE;
		}
		else
		{
			DbgPrint("Found iqvw64e.sys in PiDDBCachetable!!\n");
			//unlink from list
			RemoveEntryList(&pFoundEntry->List);
			RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
			// release the ddb resource lock
			ExReleaseResourceLite(PiDDBLock);
			DbgPrint("Clear success and finish !!!\n");
			return TRUE;
		}

	}
}



BOOLEAN isMmUnloadedDriversFilled()
{
	PMM_UNLOADED_DRIVER entry;
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		entry = &MmUnloadedDrivers[Index];
		if (entry->Name.Buffer == NULL || entry->Name.Length == 0 || entry->Name.MaximumLength == 0)
		{
			return FALSE;
		}

	}
	return TRUE;
}




BOOLEAN cleanUnloadedDriverString()
{
	findMMunloadedDrivers();
	BOOLEAN cleared = FALSE;
	BOOLEAN Filled = isMmUnloadedDriversFilled();

	DbgPrint("about to clear mmunload\n");

	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{


		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];

		if (RtlCompareUnicodeString(&DriverName, &Entry->Name, TRUE))
		{
			if (Index == 0)
			{
				RtlZeroMemory(Entry, sizeof(MM_UNLOADED_DRIVER));
			}
			else
			{
				//random 7 letter name
				RtlCopyUnicodeString(&Entry->Name, &NewDriverName);
				Entry->UnloadTime = MmUnloadedDrivers[Index - 1].UnloadTime - 50;

				DbgPrint("DONE randomizing name inside CleanUnloadedDriverString\n");
			}
			return TRUE;
		}
	}
	DbgPrint("cannot find iqvw64e.sys!!!!111 cleanunloadeddriverstring fail!!1111\n");

	return FALSE;
}


BOOLEAN		clearKdmapperTraces()
{
	BOOLEAN		status;
	status =	cleanUnloadedDriverString();
	if (status == FALSE)
	{
		DbgPrint("problem with mmunloadeddrivers\n");
	}
	status =	ClearPiddbCacheTable();
	if (status == FALSE)
	{
		DbgPrint("problem with PiddbCacheTable\n");
	}
	return	 status;
}