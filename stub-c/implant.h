#include <Windows.h>
#include <WinUser.h>

HGLOBAL GenerateHash(BYTE *, unsigned int);
HGLOBAL * GetComputerInfo(COMPUTER_NAME_FORMAT nametype);
void CheckExecution();
unsigned int HashCheck();

