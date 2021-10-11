// fuzz_me will typically be at 0x401000

#include <stdio.h>
#include <windows.h>
#include <conio.h>

#define DEBUG_LOG_FILE "toy_example.log"

#define dbg_printf (void)printf

typedef int (*test_func_t)(char*);
HMODULE hMathlib;

void check_fwrite()
{
    static int counter = 0;
    FILE *fp;
    fp = fopen(DEBUG_LOG_FILE, "a");
    fprintf(fp, "hello from toy example! counter value: %d\n", counter);
    fclose(fp);
    counter++;
}

extern "C" __declspec(dllexport) int test(char *input)
{
	char v2;
	signed int v3;
	unsigned int v4;
	char *v5;
	char v6;
	char v7;
	char v8;
	int v9;

	printf("msg:%s\n", input);
	if (input[0] != 't')
	{
		printf("Error 1\n");
		return 0;
	}
	if (input[1] != 'e')
	{
		printf("Error 2\n");
		return 0;
	}
	if (input[2] != 's')
	{
		printf("Error 3\n");
		return 0;
	}
	if (input[3] == '*')
	{
		// simple nullptr deref
		*(volatile char*)0 = 1;
		return 0;
	}
	else if (input[3] == '!')
	{
		// trigger a timeout
		Sleep(5000);
		return 0;
	}
	else if (input[3] != 't')
	{
		printf("Error 4\n");
		return 0;
	}

	// buffer overflow
	v8 = 0;
	v3 = 5;
	v9 = 0;
	do
	{
		v4 = strlen(input) + 1;
		v5 = &v7;
		do
			v6 = (v5++)[1];
		while (v6);
		memcpy(v5, input, v4);
		--v3;
	} while (v3);
	printf("buffer: %s\n", &v8);
	return 0;
}

__declspec(noinline) void __stdcall fuzz_me(char* filename)
{
    char buf[201];
    ZeroMemory(&buf, 201);
    FILE *fp = fopen(filename, "rb");
    fread(buf, 1, 200, fp);

	test_func_t test_func = test;// (test_func_t)GetProcAddress(hMathlib, "test"); // index
    int result = test_func(buf);
    printf("Result: %d\n", result);    
    fclose(fp);  

    check_fwrite();

    TerminateProcess(INVALID_HANDLE_VALUE, 0); // Won't do anything
    printf("Bye");
    TerminateProcess(GetCurrentProcess(), 0); // Should get reported as exit
    printf("We should never get here");
}

int main(int argc, char ** argv)
{
    system("del " DEBUG_LOG_FILE);

    hMathlib = LoadLibraryA("example_library.dll");
    if (hMathlib == NULL) {
        dbg_printf("failed to load example_library , GLE = %d\n", GetLastError());
        exit(1);
    }
    printf("example_library loaded at %p\n", hMathlib);

    //_getch();

    fuzz_me(argv[1]);

    printf("main() ends\n");

    return 0;
}
