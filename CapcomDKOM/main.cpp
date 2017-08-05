#include "Global.h"

int michi = 1234;
int jafar = 0;

int main()
{
	if (g_pMem->OnSetup("CapcomPhysical.exe"))	// Attach to process
	{
		std::cout << g_pMem->Read<int>(&michi) << '\n';
		HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_pMem->GetProcessIdByName("CapcomPhysical.exe"));
		g_pMem->ChangeHandleAccess(h, PROCESS_ALL_ACCESS);

		ReadProcessMemory(h, &michi, &jafar, sizeof(int), 0);
		std::cout << jafar << '\n';

		g_pMem->Detach();
	}
	std::cin.get();
	return 0;
}
