#pragma once
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>

#include "Capcom.h"
#include "KernelFuncs.h"
#include "Proc.h"

#define IOCTL_READ		1
#define IOCTL_DIRTABLE	2
#define IOCTL_CR3		3
#define IOCTL_PPEB		4
#define IOCTL_HANDLE	5
#define IOCTL_WRITE		6


#pragma comment(lib, "ntdll.lib")

typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		PVOID Object;
		ULONG ObAttributes;
		ULONG_PTR Value;
	};
	union
	{
		ACCESS_MASK GrantedAccess;
		LONG NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef enum _MEMORY_CACHING_TYPE {
	MmNonCached = 0,
	MmCached = 1,
	MmWriteCombined = 2,
	MmHardwareCoherentCached = 3,
	MmNonCachedUnordered = 4,
	MmUSWCCached = 5,
	MmMaximumCacheType = 6
} MEMORY_CACHING_TYPE;

typedef struct _READWRITE_REQ
{
	DWORD IOCTL;
	uint64_t Address;
	SIZE_T Length;
	uint64_t Buffer;
	bool Success;
}READWRITE_REQ, *PREADWRITE_REQ;

typedef struct _REQUEST
{
	DWORD IOCTL;
	HANDLE ProcessId;
	uint64_t Ret;
}REQUEST, *PREQUEST;

typedef struct _HANDLE_REQ
{
	DWORD IOCTL;
	HANDLE ProcessId;
	HANDLE Handle;
	ACCESS_MASK Access;
	bool Success;
}HANDLE_REQ, *PHANDLE_REQ;