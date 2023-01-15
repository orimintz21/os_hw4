#include <unistd.h>
#include <cstring>
using std::memmove;

void *smalloc(size_t size);
void scalloc(size_t num, size_t size);
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
    void add(MallocMetadata *node);
    void remove(MallocMetadata *node);
    MallocMetadata *getHead() const { return _head; }
    MallocMetadata *getTail() const { return _tail; }
    size_t getNumFreeBlocks() const { return _list_num_free_blocks; }
    size_t getNumFreeBytes() const { return _list_num_free_bytes; }
    size_t getNumAllocatedBlocks() const { return _list_num_allocated_blocks; }
    size_t getNumAllocatedBytes() const { return _list_num_allocated_bytes; }
    size_t getNumMetaDataBytes() const { return _list_num_meta_data_bytes; }
    size_t getSizeMetaData() const { return sizeof(MallocMetadata); }
};
