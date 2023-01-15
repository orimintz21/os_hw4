#include <unistd.h>

void *smalloc(size_t size);

void *smalloc(size_t size)
{
    if (size == 0 || size > 1024 * 1024 * 1024)
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