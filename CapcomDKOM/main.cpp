#include "Global.h"

int michi = 1234;
int jafar = 0;

int main()
{
	g_pMem->OnSetup("lelerz.exe");	// Attach to process
	
	g_pMem->GetModuleByName(L"d");

	g_pMem->Detach();
	std::cin.get();
	return 0;
}
