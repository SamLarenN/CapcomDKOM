#include "Global.h"

Proc* g_pMem = new Proc();

bool Proc::OnSetup(const char* ProcessName)
{
	hDeviceDriver = CreateFile("\\\\.\\Htsysm72FB", FILE_ALL_ACCESS, FILE_SHARE_READ, nullptr, FILE_OPEN, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hDeviceDriver == INVALID_HANDLE_VALUE)
		goto exit;

	ProcessId = GetProcessIdByName(ProcessName);
	if (!ProcessId)
		goto exit;

	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);	// For querying the WOW64 information
	if (hProc == INVALID_HANDLE_VALUE)	
		goto exit;

	if (!IsWow64Process(hProc, &IsProcess32bit))	// Check if the desired process is running in WOW64 environment
		goto exit;
	
	DirectoryTableBase = GetDirectoryTableBase();	
	if (!DirectoryTableBase)
		goto exit;

	pPEB = ReadPEBPointer();	
	if (!pPEB)
		goto exit;
	pPEB += IsProcess32bit ? 0x1000 : 0;	// If the process is 32bit, then the PEB32 is 0x1000 from the PEB64.
	

	CloseHandle(hProc);		// We only want this handle to query process info. Close it.
	return true;

exit:
	Detach();
	return false;
}

// Detach from process
void Proc::Detach()
{
	if (hDeviceDriver != INVALID_HANDLE_VALUE)
		CloseHandle(hDeviceDriver);
	if (hProc != INVALID_HANDLE_VALUE)
		CloseHandle(hProc);

	DirectoryTableBase = 0;
	pPEB = 0;
}

// Get module base and size from PEB.
module* Proc::GetModuleByName(const wchar_t* ModuleName)
{
	wchar_t* lel = new wchar_t[MAX_PATH];
	if (IsProcess32bit)
	{
		DWORD pebldr = Read<DWORD>(pPEB + 0xC);	// Read PEB_LDR_DATA*
		if (pebldr)
		{
			DWORD first = Read<DWORD>(pebldr + 0x14);	// Read first entry, (flink)
			if (first)
			{
				DWORD end = first;
				do
				{
					ZeroMemory(lel, MAX_PATH);
					DWORD dllSize = Read<DWORD>(first + 0x18);
					DWORD dllBase = Read<DWORD>(first + 0x10);

					if (!dllBase)
						return 0;

					DWORD dllbuffer = Read<DWORD>(first + 0x28);
					WORD dlllen = Read<WORD>(first + 0x24);

					Read(dllbuffer, (PVOID)lel, (size_t)dlllen);

					if (!wcscmp(lel, ModuleName))
					{
						module* mod = new module(dllBase, dllSize);
						return mod;
					}

					first = Read<DWORD>(first);
				} while (first != end);		// Walk the entirety of the modules until we are back to the start
			}
		}
	}
	else
	{
		PPEB peb = (PPEB)pPEB;
		
		PPEB_LDR_DATA pebldr = Read<PPEB_LDR_DATA>(&peb->Ldr);	// Read PEB_LDR_DATA*

		PLDR_DATA_TABLE_ENTRY first = Read<PLDR_DATA_TABLE_ENTRY>(&pebldr->InMemoryOrderModuleList);	// Read first entry, (flink)
		PLDR_DATA_TABLE_ENTRY end = first;
		do
		{
			wchar_t* lel = new wchar_t[MAX_PATH];
			ZeroMemory(lel, MAX_PATH);

			uint64_t dllSize = Read<uint64_t>((UINT64)first + 0x30);
			uint64_t dllBase = Read<uint64_t>((UINT64)first + 0x20);
			std::cout << "Base: " << std::hex << dllBase << "\nSize: " << dllSize << '\n';
			if (!dllBase)
				break;

			uint64_t dllbuffer = Read<uint64_t>((UINT64)first + 0x48 + 8);
			WORD dlllen = Read<WORD>((UINT64)first + 0x48);

			Read(dllbuffer, (PVOID)lel, (size_t)dlllen);
			printf("%S\n", lel);

			first = Read<PLDR_DATA_TABLE_ENTRY>(first);
		} while (first != end);
	}
	return 0;
}

// Get process ID using snapshot.
uint32_t Proc::GetProcessIdByName(const char* ProcessName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &pEntry))
	{
		do
		{
			if (!strcmp(pEntry.szExeFile, ProcessName))
			{
				CloseHandle(hSnap);
				return pEntry.th32ProcessID;
			}
		} while (Process32Next(hSnap, &pEntry));
	}
	CloseHandle(hSnap);
	return 0;
}

uint64_t Proc::ReadPEBPointer()
{
	if (!ProcessId)
		return 0;

	REQUEST Data{ 0 };
	Data.IOCTL = IOCTL_PPEB;
	Data.ProcessId = (HANDLE)ProcessId;

	g_pCapcomIoctl->Build(ExploitFunc, &Data);
	g_pCapcomIoctl->Run(hDeviceDriver);
	g_pCapcomIoctl->Free();

	return Data.Ret;
}

uint64_t Proc::GetDirectoryTableBase()
{
	if (!ProcessId)
		return 0;

	REQUEST Data{ 0 };
	Data.IOCTL = IOCTL_DIRTABLE;
	Data.ProcessId = (HANDLE)ProcessId;

	g_pCapcomIoctl->Build(ExploitFunc, &Data);
	g_pCapcomIoctl->Run(hDeviceDriver);
	g_pCapcomIoctl->Free();

	return Data.Ret;
}

uint64_t Proc::Read_cr3()
{
	REQUEST Data{ 0 };
	Data.IOCTL = IOCTL_CR3;

	g_pCapcomIoctl->Build(ExploitFunc, &Data);
	g_pCapcomIoctl->Run(hDeviceDriver);
	g_pCapcomIoctl->Free();

	return Data.Ret;
}

// Thanks MarkHC for this function <3.
// Too lazy to write my own xD
uint64_t Proc::TranslateVirtualAddress(PVOID VirtualAddress)
{
	if (!DirectoryTableBase)
		return 0;

	auto va = (std::uint64_t)VirtualAddress;

	auto PML4 = (USHORT)((va >> 39) & 0x1FF);
	auto DirectoryPtr = (USHORT)((va >> 30) & 0x1FF); 
	auto Directory = (USHORT)((va >> 21) & 0x1FF); 
	auto Table = (USHORT)((va >> 12) & 0x1FF); 

	auto PML4E = ReadPhysicalAddress<std::uint64_t>(DirectoryTableBase + PML4 * sizeof(ULONGLONG));

	if (PML4E == 0)
		return 0;

	auto PDPTE = ReadPhysicalAddress<std::uint64_t>((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(ULONGLONG));

	if (PDPTE == 0)
		return 0;

	if ((PDPTE & (1 << 7)) != 0) {
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);
	}

	auto PDE = ReadPhysicalAddress<std::uint64_t>((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(ULONGLONG));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0) {
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	}

	auto PTE = ReadPhysicalAddress<std::uint64_t>((PDE & 0xFFFFFFFFFF000) + Table * sizeof(ULONGLONG));

	if (PTE == 0)
		return 0;

	return (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
}

bool Proc::ReadPhysicalAddress(uint64_t address, PVOID buffer, size_t length)
{
	if (!address || !buffer || !length)
		return false;

	READWRITE_REQ Data{ 0 };

	Data.IOCTL = IOCTL_READ;
	Data.Address = address;
	Data.Length = length;
	Data.Buffer = (uint64_t)buffer;
	
	g_pCapcomIoctl->Build(ExploitFunc, &Data);
	g_pCapcomIoctl->Run(hDeviceDriver);
	g_pCapcomIoctl->Free();

	return Data.Success;
}

bool Proc::Read(uint64_t address, PVOID buffer, size_t length)
{
	uint64_t PhysicalAddress = TranslateVirtualAddress((PVOID)address);
	return ReadPhysicalAddress(PhysicalAddress, buffer, length);
}

bool Proc::ChangeHandleAccess(HANDLE handle, ACCESS_MASK Access)
{
	HANDLE_REQ Req;
	Req.IOCTL = IOCTL_HANDLE;
	Req.Access = Access;
	Req.Handle = handle;
	Req.ProcessId = (HANDLE)ProcessId;

	g_pCapcomIoctl->Build(ExploitFunc, &Req);
	g_pCapcomIoctl->Run(g_pMem->hDeviceDriver);
	g_pCapcomIoctl->Free();

	return Req.Success;
}

bool Proc::WritePhysicalAddress(uint64_t address, PVOID buffer, size_t length)
{
	if (!address || !buffer || !length)
		return false;
	
	READWRITE_REQ Data{ 0 };

	Data.IOCTL = IOCTL_WRITE;
	Data.Address = address;
	Data.Length = length;
	Data.Buffer = (uint64_t)buffer;

	g_pCapcomIoctl->Build(ExploitFunc, &Data);
	g_pCapcomIoctl->Run(hDeviceDriver);
	g_pCapcomIoctl->Free();

	return Data.Success;
}

bool Proc::Write(uint64_t address, PVOID buffer, size_t length)
{	
	uint64_t PhysicalAddress = TranslateVirtualAddress((PVOID)address);
	return WritePhysicalAddress(PhysicalAddress, buffer, length);
}
