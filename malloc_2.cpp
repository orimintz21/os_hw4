#include <unistd.h>
#include <cstring>
using std::memmove;

void *smalloc(size_t size);
void *scalloc(size_t num, size_t size);
void sfree(void *p);
void *srealloc(void *oldp, size_t size);

// internal functions
size_t _num_free_blocks();
size_t _num_free_bytes();
size_t _num_allocated_blocks();
size_t _num_allocated_bytes();
size_t _num_meta_data_bytes();
size_t _size_meta_data();
struct MallocMetadata
{
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
};

class MallocList
{
private:
    MallocList() : _head(NULL), _tail(NULL) {}
    static MallocList &_instance;
    MallocMetadata *_head;
    MallocMetadata *_tail;
    size_t _list_num_free_blocks;
    size_t _list_num_free_bytes;
    size_t _list_num_allocated_blocks;
    size_t _list_num_allocated_bytes;
    size_t _list_num_meta_data_bytes;

public:
    MallocList(const MallocList &other) = delete;
    MallocList &operator=(const MallocList &other) = delete;
    static MallocList &getInstance()
    {
        static MallocList _instance;
        return _instance;
    }
    ~MallocList() = default;
    MallocMetadata *getHead() const { return _head; }
    MallocMetadata *getTail() const { return _tail; }
    size_t getNumFreeBlocks() const { return _list_num_free_blocks; }
    size_t getNumFreeBytes() const { return _list_num_free_bytes; }
    size_t getNumAllocatedBlocks() const { return _list_num_allocated_blocks; }
    size_t getNumAllocatedBytes() const { return _list_num_allocated_bytes; }
    size_t getNumMetaDataBytes() const { return _list_num_meta_data_bytes; }
    void addLast(MallocMetadata *node);
    MallocMetadata *findData(void *data);
    MallocMetadata *findFree(size_t size);

    void *mallocData(const size_t size);
    void *callocData(const size_t num, const size_t size);
    void freeData(void *data);
    void *reallocData(void *data, const size_t size);
};

size_t _num_free_blocks()
{
    return MallocList::getInstance().getNumFreeBlocks();
}
size_t _num_free_bytes()
{
    return MallocList::getInstance().getNumFreeBytes();
}
size_t _num_allocated_blocks()
{
    return MallocList::getInstance().getNumAllocatedBlocks();
}
size_t _num_allocated_bytes()
{
    return MallocList::getInstance().getNumAllocatedBytes();
}
size_t _num_meta_data_bytes()
{
    return MallocList::getInstance().getNumMetaDataBytes();
}
size_t _size_meta_data()
{
    return sizeof(MallocMetadata);
}

// asserts that the node is allocated
void MallocList::addLast(MallocMetadata *node)
{
    if (_head == NULL)
    {
        _head = node;
        _tail = node;
        _list_num_free_blocks = 0;
        _list_num_free_bytes = 0;
        _list_num_allocated_blocks = 1;
        _list_num_allocated_bytes = node->size;
        _list_num_meta_data_bytes = _size_meta_data();
    }
    else
    {
        _tail->next = node;
        node->prev = _tail;
        _tail = node;
        _list_num_allocated_blocks++;
        _list_num_allocated_bytes += node->size;
        _list_num_meta_data_bytes += _size_meta_data();
    }
}

MallocMetadata *MallocList::findData(void *data)
{
    MallocMetadata *curr = _head;
    while (curr != NULL)
    {
        if ((void *)(curr + 1) == data)
        {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

MallocMetadata *MallocList::findFree(size_t size)
{
    MallocMetadata *curr = _head;
    while (curr != NULL)
    {
        if (curr->is_free && curr->size >= size)
        {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

void *MallocList::mallocData(const size_t size)
{
    if (size == 0 || size > 1000000000)
    {
        return NULL;
    }
    MallocMetadata *curr = findFree(size);
    // if there is a free block that is big enough
    if (curr != NULL)
    {
        curr->is_free = false;
        _list_num_free_blocks--;
        _list_num_free_bytes -= curr->size;
        return (void *)(curr + 1);
    }
    else
    {
        MallocMetadata *new_node = (MallocMetadata *)sbrk(size + _size_meta_data());
        if (new_node == (void *)-1)
        {
            return NULL;
        }
        new_node->size = size;
        new_node->is_free = false;
        new_node->next = NULL;
        new_node->prev = NULL;
        addLast(new_node);
        return (void *)(new_node + 1);
    }
}

void *MallocList::callocData(const size_t num, const size_t size)
{
    void *data = mallocData(num * size);
    if (data == NULL)
    {
        return NULL;
    }
    memset(data, 0, num * size);
    return data;
}

void MallocList::freeData(void *data)
{
    MallocMetadata *curr = findData(data);
    if (curr != NULL)
    {
        curr->is_free = true;
        _list_num_free_blocks++;
        _list_num_free_bytes += curr->size;
        _list_num_allocated_blocks--;
        _list_num_allocated_bytes -= curr->size;
    }
}

void *MallocList::reallocData(void *data, const size_t size)
{
    if (size == 0 || size > 100000000)
    {
        return NULL;
    }
    MallocMetadata *curr = findData(data);
    if (curr == NULL)
    {
        return NULL;
    }
    if (curr->size >= size)
    {
        return data;
    }
    void *new_data = mallocData(size);
    if (new_data == NULL)
    {
        return NULL;
    }
    memcpy(new_data, data, curr->size);
    freeData(data);
    return new_data;
}

void *smalloc(size_t size)
{
    return MallocList::getInstance().mallocData(size);
}

void *scalloc(const size_t num, size_t size)
{
    return MallocList::getInstance().callocData(num, size);
}

void sfree(void *p)
{
    MallocList::getInstance().freeData(p);
}

void *srealloc(void *oldp, size_t size)
{
    return MallocList::getInstance().reallocData(oldp, size);
}
