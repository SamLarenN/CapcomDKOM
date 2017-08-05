#pragma once

typedef struct _DllRet DllRet;
typedef struct _REQUEST REQUEST;
typedef enum   _MEMORY_CACHING_TYPE MEMORY_CACHING_TYPE;

typedef struct  _EPROCESS *PEPROCESS;

void __stdcall ExploitFunc(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID CustomData);

class KernelFuncs
{
public:
	

public:
	NTSTATUS(NTAPI* PsLookupProcessByProcessId)(HANDLE, PEPROCESS*);
	VOID(NTAPI* ObDereferenceObject)(PVOID);	
	ULONG(NTAPI* DbgPrintEx)(ULONG, ULONG, PCSTR, ...);
	PVOID(NTAPI* MmMapIoSpace)(LARGE_INTEGER, SIZE_T, MEMORY_CACHING_TYPE);
	VOID(NTAPI* MmUnmapIoSpace)(PVOID, SIZE_T);

	void GetSystemRoutines(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress);

	BOOLEAN m_InitializationFinished = FALSE;
};

extern KernelFuncs* g_pKernelFuncs;