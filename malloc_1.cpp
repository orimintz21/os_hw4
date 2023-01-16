#include <unistd.h>
#define MAX_SIZE 100000000

void *smalloc(size_t size);

void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }
    void *ptr = sbrk(0);
    void *request = sbrk(size);
    if (request == (void *)-1)
    {
        return NULL;
    }
    else
    {
        return ptr;
    }
}