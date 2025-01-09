// dllmain.cpp : Defines the entry point for the DLL application.
#include "../harness-api.h"
#include <stdio.h>
#include <conio.h>
#include <psapi.h>

// Adapted from winnie's toy_example harness
// cl.exe /D_USERDLL /D_WINDLL /DMAIN_OFFSET=0xdeadbeef Harness.cpp /MT /link /DLL /OUT:Harness.dll
// (You must define MAIN_OFFSET - this should be the offset from the entry point to main
// function.)

// This macro exports the HARNESS_INFO struct expected by fuzzer. The injected forkserver (injected-harness) will LoadLibrary the harness, and then use this.
EXPOSE_HARNESS(
    NULL,  // target method, we will fill this in dynamically at DllMain
    NULL,  // fuzz iter func, we will fill this in dynamically at DllMain
    NULL,  // default input file (.cur_input)
    NULL,  // no setup func needed
    FALSE, // don't need desocket
    FALSE  // Not ready yet, we initialize dynamically in DllMain.
);

HMODULE hMainModule;
LPVOID mainFunction;

LPVOID target_entry;

LPVOID getModuleEntry(HMODULE tm)
{
	MODULEINFO info;
        if(GetModuleInformation(GetCurrentProcess(), tm, &info, sizeof(info)) == 0)
        {
            DWORD err = GetLastError();
            printf("GetModuleInformation failed. GLE = %d.\n", err);
            return NULL;
        }
        return (LPVOID)info.EntryPoint;	
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hMainModule = GetModuleHandle(NULL);
        target_entry = getModuleEntry(hMainModule);
	if(!target_entry)
	{
		return FALSE;
	}
	mainFunction = (LPVOID)((char*)target_entry + MAIN_OFFSET);

	HarnessInfo.target_method = mainFunction;
	HarnessInfo.fuzz_iter_func = (void (CALLBACK *)(void))mainFunction;

	MemoryBarrier();
	InterlockedExchange8(&HarnessInfo.ready, TRUE);

	break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

