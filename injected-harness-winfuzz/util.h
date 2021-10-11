// Helper functions for winfuzz.cpp
#include <windows.h>
#include <stdio.h>
#include "freelist.h"

/// Prints the contents of a null terminated argument vector
static void printArgv(const char** vector)
{
	if (vector == NULL)
		return;

	int i = 0;
	for (const char** current = vector; *current != NULL; current++)
	{
		printf("argv[%d]: %s\n", i, *current);
		i++;
	}
}

// Converts an argument vector to a single string command line
static char* argvToCommandLine(const char** vector)
{
	unsigned commandLineLength = 0;
	for (const char** currArg = vector; *currArg != NULL; currArg++)
	{
		commandLineLength += strlen(*currArg) + 1;
	}
	char* result = (char*)malloc(sizeof(char) * commandLineLength);
	unsigned i = 0;
	for (const char** currArg = vector; *currArg != NULL; currArg++)
	{
		strcpy_s(&result[i], sizeof(char) * commandLineLength, *currArg);
		i += strlen(*currArg);
		result[i] = ' ';
		i++;
	}
	result[commandLineLength - 1] = '\0';
	return result;
}

/// Creates and returns a copy of a null terminated argument vector
static char** copyArgv(const char** vector)
{
	if (vector == NULL)
		return NULL;

	char** result = NULL;
	int numArgs = 0;
	for (const char** current = vector; *current != NULL; current++)
	{
		numArgs++;
	}

	result = (char**)malloc(sizeof(char*) * (numArgs + 1));
	for (int i = 0; i < numArgs; i++)
	{
		result[i] = (char*)malloc(strlen(vector[i]) + 1);
		strcpy_s(result[i], sizeof(char) * (numArgs + 1), vector[i]);
	}
	result[numArgs] = NULL;

	return result;
}

/// copyArgv with a FreeList parameter
static char** copyArgv(const char** vector, FreeList* list)
{
	if (vector == NULL)
		return NULL;

	char** result = NULL;
	int numArgs = 0;
	for (const char** current = vector; *current != NULL; current++)
	{
		numArgs++;
	}

	result = (char**)malloc(sizeof(char*) * (numArgs + 1));
	list->add(result);
	for (int i = 0; i < numArgs; i++)
	{
		result[i] = (char*)malloc(strlen(vector[i]) + 1);
		list->add(result[i]);
		strcpy_s(result[i], sizeof(char*) * (numArgs + 1), vector[i]);
	}
	result[numArgs] = NULL;

	return result;
}

/// Frees all memory associated with a null terminated argument vector
static void freeArgv(char** vector)
{
	if (vector == NULL)
		return;

	for (char** current = vector; *current != NULL; current++)
	{
		free(*current);
	}
	free(vector);
}

// Prints the error text associated with a DWORD returned from GetLastError()
static void printErrorCode(DWORD code)
{
	LPVOID messageBuffer = NULL;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		code,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&messageBuffer,
		0,
		NULL);

	printf("%s", (char*)messageBuffer);
	LocalFree(messageBuffer);
}

// Trims an absolute path to the name of the file/directory it points to
static char* endOfPath(char* path)
{
	char* result = path + strlen(path);
	while (*(result - 1) != '\\' && *(result - 1) != '/' && result > path)
	{
		result--;
	}
	return result;
}

// Trims a path to just the directory
static char* pathName(char* path)
{
	size_t nameLength = strlen(endOfPath(path));
	size_t resultLength = strlen(path) - nameLength + 1;
	char* result = (char*)malloc(resultLength);
	memcpy(result, path, resultLength);
	result[resultLength - 1] = '\0';
	return result;
}

// Lowercases a string
static char* lowercase(char* str)
{
	for (int i = 0; str[i]; i++)
	{
		str[i] = tolower(str[i]);
	}
	return str;
}

// Returns the address of the executable module's entry point
static void* getExeEntry()
{
	char exeName[512];
	if (GetProcessImageFileNameA(GetCurrentProcess(), exeName, 512) == 0)
	{
		printf("GetProcessImageFileName failed.\n");
		return NULL;
	}
	HMODULE modules[16];
	DWORD bytesNeeded = 0;
	if (EnumProcessModules(GetCurrentProcess(), modules, 16 * sizeof(HMODULE), &bytesNeeded) == 0)
	{
		printf("failed\n.");
		return NULL;
	}
	int numRecieved = bytesNeeded / sizeof(HMODULE);
	//printf("recieved %d process modules\n", numRecieved);
	for (int i = 0; i < numRecieved; i++)
	{
		char fileName[512];
		if (GetModuleFileNameExA(GetCurrentProcess(), modules[i], fileName, 512) == 0)
		{
			printf("failed.\n");
			continue;
		}
		//printf("Checking for entry point of %s\n", fileName);
		if (strcmp(endOfPath(exeName), endOfPath(fileName)) == 0)
		{
			MODULEINFO info;
			if (GetModuleInformation(GetCurrentProcess(), modules[i], &info, sizeof(info)) == 0)
			{
				DWORD err = GetLastError();
				printf("GetModuleInformation failed.\n");
				printErrorCode(err);
				return NULL;
			}
			return info.EntryPoint;
		}
	}
	return NULL;
}

// Returns the address of the executable module's base
static void* getExeBase()
{
	char exeName[512];
	if (GetProcessImageFileNameA(GetCurrentProcess(), exeName, 512) == 0)
	{
		printf("GetProcessImageFileName failed.\n");
		return NULL;
	}
	HMODULE modules[16];
	DWORD bytesNeeded = 0;
	if (EnumProcessModules(GetCurrentProcess(), modules, 16 * sizeof(HMODULE), &bytesNeeded) == 0)
	{
		printf("failed\n.");
		return NULL;
	}
	int numRecieved = bytesNeeded / sizeof(HMODULE);
	//printf("recieved %d process modules\n", numRecieved);
	for (int i = 0; i < numRecieved; i++)
	{
		char fileName[512];
		if (GetModuleFileNameExA(GetCurrentProcess(), modules[i], fileName, 512) == 0)
		{
			printf("failed.\n");
			continue;
		}
		//printf("Checking for entry point of %s\n", fileName);
		if (strcmp(endOfPath(exeName), endOfPath(fileName)) == 0)
		{
			MODULEINFO info;
			if (GetModuleInformation(GetCurrentProcess(), modules[i], &info, sizeof(info)) == 0)
			{
				DWORD err = GetLastError();
				printf("GetModuleInformation failed.\n");
				printErrorCode(err);
				return NULL;
			}
			return info.lpBaseOfDll;
		}
	}
	return NULL;
}

void attachDetour(PVOID* original, PVOID hook, const char* name)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	printf("Detouring %s at %p\n", name, *original);
	DetourAttach(original, hook);

	LONG error = DetourTransactionCommit();
	if (error == NO_ERROR) {
		printf("echofx" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
			" Detoured %s().\n", name);
	}
	else {
		printf("echofx" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
			" Error detouring %s(): %d\n", name, error);
	}
}

void detachDetour(PVOID* original, PVOID hook, const char* name)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	printf("Attempting to remove %s detour...", name);
	DetourDetach(original, hook);

	LONG error = DetourTransactionCommit();
	if (error == NO_ERROR) {
		printf("succeeded.\n");
	}
	else {
		printf("failed (%lu).\n", error);
	}
}