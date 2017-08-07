#pragma once

// Module class base.
class module
{
public:
	const uint64_t dwBase, dwSize;

public:
	module(uint64_t base, uint64_t size)
		: dwBase(base),
		dwSize(size)
	{
	}

};


class Proc
{
public:
	bool OnSetup(const char* ProcessName);
	void Detach();
	uint32_t GetProcessIdByName(const char* ProcessName);
	module* GetModuleByName(const wchar_t* ModuleName);

	bool ChangeHandleAccess(HANDLE handle, ACCESS_MASK Access);

	bool ReadPhysicalAddress(uint64_t address, PVOID buffer, size_t length);
	template<typename T, typename U>
	T ReadPhysicalAddress(U address)
	{
		T buffer{ 0 };
		ReadPhysicalAddress(address, &buffer, sizeof(T));
		return buffer;
	}

	bool Read(uint64_t address, PVOID buffer, size_t length);
	template<typename T, typename U>
	T Read(U address)
	{
		T buffer{ 0 };
		Read((uint64_t)address, &buffer, sizeof(T));
		return buffer;
	}
	
	bool WritePhysicalAddress(uint64_t address, PVOID buffer, size_t length);
	template<typename T, typename U>
	bool WritePhysicalAddress(U address, T val)
	{
		return WritePhysicalAddress(address, &val, sizeof(T));
	}

	bool Write(uint64_t address, PVOID buffer, size_t length);
	template<typename T, typename U>
	bool Write(U address, T val)
	{
		return Write((uint64_t)address, &val, sizeof(T));
	}

private:
	uint64_t GetDirectoryTableBase();
	uint64_t Read_cr3();
	uint64_t ReadPEBPointer();
	
	uint64_t TranslateVirtualAddress(PVOID VirtualAddress);

	HANDLE hProc = INVALID_HANDLE_VALUE;
	BOOL IsProcess32bit;
	uint64_t DirectoryTableBase = 0;
	HANDLE hDeviceDriver = INVALID_HANDLE_VALUE;
	uint32_t ProcessId = -1;
	uint64_t pPEB = 0;
};

extern Proc* g_pMem;
