#include <vector>
#include "winfuzz.h"

class FreeList
{
public:
	FreeList() {}
	~FreeList() {}

	void freeAll()
	{
		for (unsigned i = 0; i < list.size(); i++)
		{
			free(list[i]);
		}
		list.clear();
	}
	void add(void* ptr) { list.push_back(ptr); }

private:
	Vector<void*> list = {};


};
