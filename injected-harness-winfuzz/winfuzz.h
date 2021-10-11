#include <Windows.h>

#pragma once

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
void*  (_cdecl* real_realloc_ptr)(void* mem, size_t new_size) = realloc;
void*  (_cdecl* real_calloc_ptr)(size_t count, size_t size) = calloc;
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

	~Vector() {
		real_free_ptr(arr);
	}

};

typedef struct heap_alloc_metadata {

	HANDLE heap;
	DWORD dw_flags;
	LPVOID mem;

	bool operator==(const heap_alloc_metadata& other) {
		return (mem == other.mem);
	}

} heap_alloc_metadata_t;

Vector<heap_alloc_metadata> heap_alloc_chunks = {};
Vector<void *> malloc_chunks = {};
Vector<void *>virtual_alloc_chunks = {};

void* malloc_hook(size_t size) {
	if (!in_target)
		return real_malloc_ptr(size);

	void* chunk_ptr = real_malloc_ptr(size);

	malloc_chunks.push_back(chunk_ptr);

	return chunk_ptr;
}

void* realloc_hook(void* mem, size_t new_size) {
	if (!in_target)
		return real_realloc_ptr(mem, new_size);

	void * chunk_ptr = real_realloc_ptr(mem, new_size);

	if (chunk_ptr != mem) {
		malloc_chunks.push_back(chunk_ptr);
	}

	return chunk_ptr;
}

void* calloc_hook(size_t count, size_t size) {
	if (!in_target)
		return real_calloc_ptr(count, size);

	void* chunk_ptr = real_calloc_ptr(count, size);
	malloc_chunks.push_back(chunk_ptr);
	return chunk_ptr;

}

void free_hook(void* ptr) {
	if (!in_target) {
		real_free_ptr(ptr);
		return;
	}

	int idx = malloc_chunks.find(ptr);

	if (idx != -1) {
		malloc_chunks[idx] = NULL;
		return real_free_ptr(ptr);
	}
}


LPVOID __stdcall heap_alloc_hook(HANDLE heap, DWORD dw_flags, SIZE_T dw_bytes) {
	if (!in_target)
		return real_heap_alloc_ptr(heap, dw_flags, dw_bytes);

	void* chunk_ptr = real_heap_alloc_ptr(heap, dw_flags, dw_bytes);

	if (!chunk_ptr) {
		heap_alloc_chunks.push_back({ heap, dw_flags, chunk_ptr });

	}

	return chunk_ptr;

}

BOOL __stdcall heap_free_hook(HANDLE heap, DWORD dw_flags, _Frees_ptr_opt_ LPVOID mem) {
	if (!in_target)
		return real_heap_free_ptr(heap, dw_flags, mem);

	heap_alloc_metadata_t h = { heap, dw_flags, mem };
	int idx = heap_alloc_chunks.find(h);
	if (idx != -1) {
		heap_alloc_chunks[idx] = {};

		return real_heap_free_ptr(heap, dw_flags, mem);

	}
	return true;
}

LPVOID virtual_alloc_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
	if (!in_target)
		return real_virtual_alloc_ptr(lpAddress, dwSize, flAllocationType, flProtect);

	void* chunk_ptr = real_virtual_alloc_ptr(lpAddress, dwSize, flAllocationType, flProtect);

	virtual_alloc_chunks.push_back(chunk_ptr);
	return chunk_ptr;
}

BOOL virtual_free_hook(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType) {
	if (!in_target)
		return real_virtual_free_ptr(lpAddress, dwSize, dwFreeType);

	int idx = virtual_alloc_chunks.find(lpAddress);

	if (idx != -1) {
		return real_virtual_free_ptr(lpAddress, dwSize, dwFreeType);
	}

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