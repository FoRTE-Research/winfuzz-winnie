#include <Windows.h>

#pragma once

#define LOG_FILE "alloc_log"
static FILE* log_file = NULL;
static char fmt_buf[4096];
static unsigned int times_run = 0;
static FILE** fuzzer_stdout_handle = NULL;
#define winfuzz_fuzzer_printf(...) fprintf(*fuzzer_stdout_handle, ##__VA_ARGS__##);

// Just a single 4 KB page
struct Page {
	char bytes[4096];
};

// A copy of a PE file section
struct SectionCopy {
	union
	{
		char* start;	// vaddr of actual section
		Page* pages;
	};
	int size;			// size in bytes
	Page* ptr;			// pointer to copy
	char name[9];		// name of section
};

// Disable hooks while executing target
static bool in_target = false;
static DWORD target_code_start = 0;
static DWORD target_code_size = 0;

void* malloc_hook(size_t size);
void* realloc_hook(void* mem, size_t new_size);
void  free_hook(void* mem);
LPVOID __stdcall heap_alloc_hook(HANDLE heap, DWORD dw_flags, SIZE_T dw_bytes);
BOOL __stdcall heap_free_hook(HANDLE heap, DWORD dw_flags, _Frees_ptr_opt_ LPVOID mem);
LPVOID virtual_alloc_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
BOOL virtual_free_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);


// Function pointers for the standard functions we're going to hook.
void(*real_exit_pointer)(int a) = exit;
void*  (*real_malloc_ptr)(size_t size) = malloc;
void(_cdecl* real_free_ptr)(void* mem) = free;
LPVOID(__stdcall* real_heap_alloc_ptr)(HANDLE heap, DWORD dw_flags, SIZE_T dw_bytes) = HeapAlloc;
BOOL(__stdcall* real_heap_free_ptr)(HANDLE heap, DWORD dw_flags, _Frees_ptr_opt_ LPVOID mem) = HeapFree;
void*  (__cdecl* real_realloc_ptr)(void* mem, size_t new_size) = realloc;
void*  (__cdecl* real_calloc_ptr)(size_t count, size_t size) = calloc;
LPVOID(__stdcall* real_virtual_alloc_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) = VirtualAlloc;
BOOL(__stdcall* real_virtual_free_ptr)(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType) = VirtualFree;


unsigned int nextPowerOf2(unsigned int n)
{
	unsigned count = 0;

	// First n in the below condition
	// is for the case where n is 0
	// if (n && !(n & (n - 1)))
	//     return n;

	while (n != 0)
	{
		n >>= 1;
		count += 1;
	}

	return 1 << count;
}

template <typename T>
class Vector {
private:
	unsigned int siz = 0;
	unsigned int capacity = 0;
	T * arr = NULL;
public:
	Vector() {
	}

	void push_back(T object) {
		if (capacity <= siz) {
			capacity = nextPowerOf2(siz);
			arr = (T *)real_realloc_ptr(arr, capacity * sizeof(T));
		}
		arr[siz] = object;
		siz++;
	}

	void clear() {
		siz = 0;
	}
	int size() {
		return siz;
	}

	void reserve(size_t new_cap) {
		if (new_cap < capacity)
			return;
		arr = (T *)real_realloc_ptr(arr, sizeof(T)*new_cap);
		capacity = new_cap;
		return;
	}

	int find(T object) {
		for (int i = 0; i < siz; ++i) {
			if (object == arr[i])
				return i;
		}
		return -1;
	}

	T& operator[](int idx) {
		return arr[idx];
	}
	
	void erase(int idx) {
		for (int i = idx; i < siz - 1; ++i) {
			arr[i] = arr[i + 1];
		}
		siz--;
	}

	~Vector() {
		real_free_ptr(arr);
	}

};

typedef struct heap_alloc_metadata {

	HANDLE heap;
	DWORD dw_flags;
	LPVOID mem;

	bool operator==(const heap_alloc_metadata& other) {
		return (mem == other.mem) && (heap == other.heap);
	}

} heap_alloc_metadata_t;

Vector<heap_alloc_metadata> heap_alloc_chunks = {};
Vector<void *> malloc_chunks = {};
Vector<void *> virtual_alloc_chunks = {};

DWORD saved_eax;
void* calloc_origin;
void* calloc_chunk;
DWORD calloc_num;
DWORD calloc_size;
char* stack_pointer;
DWORD parameters[5];

DWORD current_ret_val = NULL;

//#define WINFUZZ_DEBUG

#ifdef WINFUZZ_DEBUG
#define WINFUZZ_LOG(...) \
fprintf(log_file, ##__VA_ARGS__##); \
fflush(log_file);
#else
#define WINFUZZ_LOG(...)
#endif

void* malloc_hook(size_t size) {
	_asm {
		mov[stack_pointer], ebp
	}
	memcpy(parameters, stack_pointer, sizeof(parameters));
	if (!in_target)
		return real_malloc_ptr(size);

	current_ret_val = parameters[1];
	in_target = false;
	void* chunk_ptr = real_malloc_ptr(size);

	// Check to see where call originated from
	//WINFUZZ_LOG("\tParameters: %x %x %x %x %x\n", parameters[0], parameters[1], parameters[2], parameters[3], parameters[4]);
	if (current_ret_val > target_code_start + target_code_size || current_ret_val < target_code_start) {
		WINFUZZ_LOG("Rejected malloc from %x\n", current_ret_val);
		in_target = true;
		return chunk_ptr;
	}

	WINFUZZ_LOG("Target malloc: %p (from %x)\n", chunk_ptr, current_ret_val);
	malloc_chunks.push_back(chunk_ptr);
	in_target = true;
	return chunk_ptr;
}

void* realloc_hook(void* mem, size_t new_size) {
	_asm {
		mov[stack_pointer], ebp
	}
	memcpy(parameters, stack_pointer, sizeof(parameters));
	static DWORD origin = parameters[1];
	if (!in_target)
		return real_realloc_ptr(mem, new_size);

	in_target = false;
	void * chunk_ptr = real_realloc_ptr(mem, new_size);
	WINFUZZ_LOG("Target realloc of size %u returned %p (original: %p)\n", new_size, chunk_ptr, mem);
	if (chunk_ptr != mem) {
		// Reject calls from outside target
		if (origin > target_code_start + target_code_size || origin < target_code_start) {
			WINFUZZ_LOG("Rejected realloc from %x\n", origin);
			in_target = true;
			return chunk_ptr;
		}

		int idx = -1;
		if ((idx = malloc_chunks.find(mem)) != -1) {
			malloc_chunks.erase(idx);
		}
		malloc_chunks.push_back(chunk_ptr);
	}

	in_target = true;
	return chunk_ptr;
}

void* __cdecl calloc_hook_no_stack(size_t count, size_t size) {
	_asm {
		mov [stack_pointer], ebp
	}
	memcpy(parameters, stack_pointer, sizeof(parameters));
	static DWORD origin = parameters[1];
	if (!in_target) {
		return real_calloc_ptr(count, size);
	}

	// Check to see where call originated from
	in_target = false;
	calloc_chunk = real_calloc_ptr(count, size);
	WINFUZZ_LOG("calloc from %p returned %p (size %u)\n", origin, calloc_chunk, count * size);
	//WINFUZZ_LOG("\tParameters: %x %x %x %x %x\n", parameters[0], parameters[1], parameters[2], parameters[3], parameters[4]);
	if (origin > target_code_start + target_code_size || origin < target_code_start) {
		WINFUZZ_LOG("Rejected calloc from %x\n", origin);
		in_target = true;
		return calloc_chunk;
	}
	else {
		WINFUZZ_LOG("Tracking calloc from %x\n", origin);
	}

	
	if (calloc_chunk) {
		malloc_chunks.push_back(calloc_chunk);
	}
	//log_calloc(calloc_origin, calloc_chunk, count, size);
	//winfuzz_fuzzer_printf("calloc returned %p (size %u)\n", calloc_chunk, count * size);
	in_target = true;
	return calloc_chunk;
}

void free_hook(void* ptr) {
	_asm {
		mov[stack_pointer], esp
	}
	if (!in_target) {
		real_free_ptr(ptr);
		return;
	}

	in_target = false;
	memcpy(parameters, stack_pointer, sizeof(parameters));
	static DWORD origin = parameters[1];
	WINFUZZ_LOG("hooked free\n");
	//WINFUZZ_LOG("\tParameters: %x %x %x %x %x\n", parameters[0], parameters[1], parameters[2], parameters[3], parameters[4]);

	// Check to see where call originated from
	if (origin > target_code_start + target_code_size || origin < target_code_start) {
		in_target = true;
		return;
	}

	int idx = malloc_chunks.find(ptr);

	if (idx != -1) {
		WINFUZZ_LOG("Erasing %p from malloc_chunks\n", malloc_chunks[idx]);
		malloc_chunks.erase(idx);
		in_target = true;
		return real_free_ptr(ptr);
	}
	else {
		WINFUZZ_LOG("Didn't find %p in list, not freeing\n", ptr);
	}
	in_target = true;
}


LPVOID __stdcall heap_alloc_hook(HANDLE heap, DWORD dw_flags, SIZE_T dw_bytes) {
	_asm {
		mov[stack_pointer], ebp
	}
	memcpy(parameters, stack_pointer, sizeof(parameters));
	if (!in_target)
		return real_heap_alloc_ptr(heap, dw_flags, dw_bytes);

	void* chunk_ptr = real_heap_alloc_ptr(heap, dw_flags, dw_bytes);

	// Check to see where call originated from
	in_target = false;
	if (parameters[1] > target_code_start + target_code_size || parameters[1] < target_code_start) {
		WINFUZZ_LOG("Rejecting HeapAlloc from outside target (%x) returning (%p) \n", parameters[1], chunk_ptr);
		in_target = true;
		return chunk_ptr;
	}

	WINFUZZ_LOG("Target HeapAlloc (heap=%p, dw_flags=%x, dw_bytes=%u) returned %p\n", heap, dw_flags, dw_bytes, chunk_ptr);
	if (chunk_ptr) {
		heap_alloc_metadata n = {};
		n.heap = heap;
		n.dw_flags = dw_flags;
		n.mem = chunk_ptr;
		heap_alloc_chunks.push_back(n);
	}

	in_target = true;
	return chunk_ptr;
}

BOOL __stdcall heap_free_hook(HANDLE heap, DWORD dw_flags, _Frees_ptr_opt_ LPVOID mem) {
	_asm {
		mov[stack_pointer], ebp
	}
	memcpy(parameters, stack_pointer, sizeof(parameters));
	if (!in_target)
		return real_heap_free_ptr(heap, dw_flags, mem);

	// Check to see where call originated from
	in_target = false;
	if (parameters[1] > target_code_start + target_code_size || parameters[1] < target_code_start) {
		WINFUZZ_LOG("Rejecting HeapFree from outside target (%x)\n", parameters[1]);
		in_target = true;
		return real_heap_free_ptr(heap, dw_flags, mem);
	}

	WINFUZZ_LOG("Target HeapFree (heap=%p, dw_flags=%x, mem=%p)\n", heap, dw_flags, mem);
	heap_alloc_metadata_t h = { heap, dw_flags, mem };
	int idx = heap_alloc_chunks.find(h);
	if (idx != -1) {
		heap_alloc_chunks.erase(idx);
		in_target = true;
		return real_heap_free_ptr(heap, dw_flags, mem);
	}
	else {
		WINFUZZ_LOG("Could not find metadata for HeapFree (heap=%p, dw_flags=%x, mem=%p\n", heap, dw_flags, mem);
	}
	in_target = true;
	return true;
}

LPVOID virtual_alloc_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
	_asm {
		mov[stack_pointer], ebp
	}
	memcpy(parameters, stack_pointer, sizeof(parameters));
	if (!in_target)
		return real_virtual_alloc_ptr(lpAddress, dwSize, flAllocationType, flProtect);

	void* chunk_ptr = real_virtual_alloc_ptr(lpAddress, dwSize, flAllocationType, flProtect);

	in_target = false;
	if (parameters[1] > target_code_start + target_code_size || parameters[1] < target_code_start) {
		WINFUZZ_LOG("Rejecting VirtualAlloc from outside target (%x)\n", parameters[1]);
		in_target = true;
		return chunk_ptr;
	}

	WINFUZZ_LOG("Target VirtualAlloc (lpAddress=%p, dwSize=%u, flAllocationType=%x, flProtect=%x)\n", lpAddress, dwSize, flAllocationType, flProtect);

	virtual_alloc_chunks.push_back(chunk_ptr);
	in_target = true;
	return chunk_ptr;
}

BOOL virtual_free_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType) {
	_asm {
		mov[stack_pointer], ebp
	}
	memcpy(parameters, stack_pointer, sizeof(parameters));
	if (!in_target)
		return real_virtual_free_ptr(lpAddress, dwSize, dwFreeType);

	in_target = false;
	if (parameters[1] > target_code_start + target_code_size || parameters[1] < target_code_start) {
		WINFUZZ_LOG("Rejecting VirtualFree from outside target (%x)\n", parameters[1]);
		in_target = true;
		return true;
	}

	WINFUZZ_LOG("Target VirtualFree (lpAddress=%p, dwSize=%u, dwFreeType=%x)\n", lpAddress, dwSize, dwFreeType);
	int idx = virtual_alloc_chunks.find(lpAddress);

	if (idx != -1) {
		virtual_alloc_chunks.erase(idx);
		in_target = true;
		return real_virtual_free_ptr(lpAddress, dwSize, dwFreeType);
	}

	in_target = true;
	return false;
}

Vector<Page*> modifiedPages;

// WinFuzz guard page handler code
// Note - reads in a guarded page will still trigger a guard page exception
LONG WINAPI guard_handler(EXCEPTION_POINTERS* exceptionInfo)
{
	if (exceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		//puts("Caught a guard page exception");
		//printf("at %p\n", PVOID(exceptionInfo->ExceptionRecord->ExceptionInformation[1]));
		PVOID exceptionAddress = PVOID(exceptionInfo->ExceptionRecord->ExceptionInformation[1]);
		if (exceptionAddress == NULL)
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}
		DWORD pageStart = DWORD(exceptionAddress) - (DWORD(exceptionAddress) % sizeof(Page));
		//printf("pageStart: %p\n", PVOID(pageStart));
		modifiedPages.push_back((Page*)pageStart);
#ifdef SEGFAULT_GUARD
		// Replace write permissions so execution can continue
		DWORD oldProtect;
		if (VirtualProtect(PVOID(pageStart), 1, PAGE_READWRITE, &oldProtect) == 0)
		{
			printf("ERROR: Could not replace write protection on page %p\n", PVOID(pageStart));
		}
#endif
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

PVOID veh_handle = nullptr;
void install_guard_handler()
{
	veh_handle = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)guard_handler);
	if (veh_handle == NULL)
		printf("Error: could not add vectored exception handler\n");
}

void remove_guard_handler()
{
	RemoveVectoredExceptionHandler(veh_handle);
}