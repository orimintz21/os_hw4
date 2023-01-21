#include <unistd.h>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <sys/mman.h>
#include <stdio.h>

#define MAP_SIZE (128 * 1024)
#define MIN_SIZE (128)
#define MAX_SIZE (1e8)

typedef enum
{
    ADD,
    REMOVE
} ADD_REMOVE;

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
    int _cookie;
    size_t size;
    bool is_free;
    bool is_mapped;
    MallocMetadata *next;
    MallocMetadata *prev;
    MallocMetadata *next_by_address;
    MallocMetadata *prev_by_address;
    MallocMetadata() : _cookie(0), size(0), is_free(false), is_mapped(false), next(nullptr), prev(nullptr) {}
};

class MallocList
{
public:
    MallocMetadata *_head;
    MallocMetadata *_tail;
    MallocMetadata *_head_by_address;
    MallocMetadata *_tail_by_address;
    MallocMetadata *_head_mapped;
    MallocMetadata *_tail_mapped;
    int _cookie;
    size_t _list_num_free_blocks;
    size_t _list_num_free_bytes;
    size_t _list_num_allocated_blocks;
    size_t _list_num_allocated_bytes;
    size_t _list_num_meta_data_bytes;
    MallocList() : _head(nullptr), _tail(nullptr), _head_by_address(nullptr), _tail_by_address(nullptr),
                   _head_mapped(nullptr), _tail_mapped(nullptr), _cookie(0)
    {
        std::srand(std::time(nullptr)); // use current time as seed for random generator
        _cookie = std::rand();
    }
    size_t getNumFreeBlocks() const { return _list_num_free_blocks; }
    size_t getNumFreeBytes() const { return _list_num_free_bytes; }
    size_t getNumAllocatedBlocks() const { return _list_num_allocated_blocks; }
    size_t getNumAllocatedBytes() const { return _list_num_allocated_bytes; }
    size_t getNumMetaDataBytes() const { return _list_num_meta_data_bytes; }

    // internal functions ---------------------------------------------------------
    void setNewMetadata(MallocMetadata *meta, size_t size, bool is_free, bool is_mapped);

    //! changes the stats of list
    void updateValuesForMallocList(MallocMetadata *meta, ADD_REMOVE add_remove);
    void changeToFree(MallocMetadata *meta);
    void changeToUsed(MallocMetadata *meta);

    MallocMetadata *findFree(size_t size);
    void checkCookie(MallocMetadata *meta);
    bool canSplit(MallocMetadata *meta, size_t size);
    MallocMetadata *splitBlocks(MallocMetadata *meta, size_t size);
    bool nextIsFree(MallocMetadata *meta);
    bool prevIsFree(MallocMetadata *meta);
    bool lowerSumIsEnough(MallocMetadata *meta, size_t size);
    bool upperSumIsEnough(MallocMetadata *meta, size_t size);
    bool lowerAndUpperSumIsEnough(MallocMetadata *meta, size_t size);
    void expend(MallocMetadata *meta, size_t size);
    MallocMetadata *getNext(MallocMetadata *meta);
    MallocMetadata *getPrev(MallocMetadata *meta);
    //! does'nt effects the stats
    void removeFromList(MallocMetadata *meta);
    void removeFromAddressList(MallocMetadata *meta);
    void removeFromSizeList(MallocMetadata *meta);
    void removeFromMappedList(MallocMetadata *meta);
    void addToList(MallocMetadata *meta);
    void addToAddressList(MallocMetadata *meta);
    void addToSizeList(MallocMetadata *meta);
    void addToMappedList(MallocMetadata *meta);
    MallocMetadata *mergeWithNext(MallocMetadata *meta);
    MallocMetadata *mergeWithPrev(MallocMetadata *meta);

    bool isWilderness(MallocMetadata *meta);
    bool higherIsWilderness(MallocMetadata *meta);
    void *getData(MallocMetadata *meta);
    MallocMetadata *getMetadata(void *p);
    void makePointersToNull(MallocMetadata *meta);
    // --------------------------------------------
    // smalloc functions
    void *smalloc(size_t size);
    void *mallocMap(size_t size);
    void *mallocList(size_t size);
    void *mallocWithFreeBlock(MallocMetadata *free_block, size_t size);
    void *mallocWithNoFreeBlock(size_t size);
    void *mallocUsingWilderness(size_t size);

    // scalloc functions
    void *scalloc(size_t num, size_t size);

    // sfree functions
    void sfree(void *p);
    void freeMap(MallocMetadata *meta);
    void freeList(MallocMetadata *meta);

    // srealloc functions
    void *srealloc(void *oldp, size_t size);
    void *reallocMap(MallocMetadata *meta, size_t size);
    void *reallocList(MallocMetadata *meta, size_t size);
    void *reallocLower(MallocMetadata *meta, size_t size);
    void *reallocUpper(MallocMetadata *meta, size_t size);
    void *reallocLowerAndUpper(MallocMetadata *meta, size_t size);
    void *reallocWilderness(MallocMetadata *meta, size_t size);
    void *reallocBothHigherIsWilderness(MallocMetadata *meta, size_t size);
    void *reallocHigherIsWilderness(MallocMetadata *meta, size_t size);
    void *useMallocForRealloc(MallocMetadata *meta, size_t size);
    void *reallocMapToSmall(MallocMetadata *meta, size_t size);
};

MallocList malloc_list;
// internal functions ---------------------------------------------------------
void MallocList::setNewMetadata(MallocMetadata *meta, size_t size, bool is_free, bool is_mapped)
{
    meta->_cookie = _cookie;
    meta->size = size;
    meta->is_free = is_free;
    meta->is_mapped = is_mapped;
    meta->next = nullptr;
    meta->prev = nullptr;
    meta->next_by_address = nullptr;
    meta->prev_by_address = nullptr;
}

void MallocList::updateValuesForMallocList(MallocMetadata *meta, ADD_REMOVE add_remove)
{
    if (add_remove == ADD)
    {
        if (meta->is_free)
        {
            _list_num_free_blocks++;
            _list_num_free_bytes += meta->size;
        }
        _list_num_allocated_blocks++;
        _list_num_allocated_bytes += meta->size;
        _list_num_meta_data_bytes += sizeof(MallocMetadata);
    }
    else
    {
        if (meta->is_free)
        {
            _list_num_free_blocks--;
            _list_num_free_bytes -= meta->size;
        }
        _list_num_allocated_blocks--;
        _list_num_allocated_bytes -= meta->size;
        _list_num_meta_data_bytes -= sizeof(MallocMetadata);
    }
}

MallocMetadata *MallocList::findFree(size_t size)
{
    MallocMetadata *curr = _head;
    while (curr != nullptr)
    {
        checkCookie(curr);
        if (curr->is_free && curr->size >= size)
        {
            return curr;
        }
        curr = curr->next;
    }
    return nullptr;
}

void MallocList::checkCookie(MallocMetadata *meta)
{
    if (meta == nullptr)
        return;
    if (meta->_cookie != _cookie)
    {
        exit(0xdeadbeef);
    }
}

void MallocList::changeToFree(MallocMetadata *meta)
{
    meta->is_free = true;
    _list_num_free_blocks++;
    _list_num_free_bytes += meta->size;
}

void MallocList::changeToUsed(MallocMetadata *meta)
{
    meta->is_free = false;
    _list_num_free_blocks--;
    _list_num_free_bytes -= meta->size;
}

bool MallocList::canSplit(MallocMetadata *meta, size_t size)
{
    return meta->size >= MIN_SIZE + size + sizeof(MallocMetadata);
}

MallocMetadata *MallocList::splitBlocks(MallocMetadata *meta, size_t size)
{
    removeFromList(meta);
    MallocMetadata *new_meta = (MallocMetadata *)((char *)meta + sizeof(MallocMetadata) + size);
    setNewMetadata(new_meta, meta->size - size - sizeof(MallocMetadata), true, false);
    meta->size = size;
    meta->is_free = false;
    addToList(new_meta);
    addToList(meta);
    if (nextIsFree(new_meta))
    {
        mergeWithNext(new_meta);
    }
    return meta;
}

void MallocList::removeFromList(MallocMetadata *meta)
{
    removeFromAddressList(meta);
    removeFromSizeList(meta);
    updateValuesForMallocList(meta, REMOVE);
    makePointersToNull(meta);
}

void MallocList::removeFromAddressList(MallocMetadata *meta)
{
    checkCookie(meta->prev_by_address);
    checkCookie(meta->next_by_address);
    checkCookie(meta);
    if (meta->prev_by_address == nullptr)
    {
        _head_by_address = meta->next_by_address;
    }
    else
    {
        meta->prev_by_address->next_by_address = meta->next_by_address;
    }
    if (meta->next_by_address == nullptr)
    {
        _tail_by_address = meta->prev_by_address;
    }
    else
    {
        meta->next_by_address->prev_by_address = meta->prev_by_address;
    }
}

void MallocList::removeFromSizeList(MallocMetadata *meta)
{
    checkCookie(meta->prev);
    checkCookie(meta->next);
    checkCookie(meta);
    if (meta->prev == nullptr)
    {
        _head = meta->next;
    }
    else
    {
        checkCookie(meta->prev);
        checkCookie(meta->next);
        meta->prev->next = meta->next;
    }
    if (meta->next == nullptr)
    {
        _tail = meta->prev;
    }
    else
    {
        meta->next->prev = meta->prev;
    }
}

void MallocList::removeFromMappedList(MallocMetadata *meta)
{
    if (meta->next == nullptr)
    {
        _head_mapped = meta->next;
    }
    else
    {
        meta->prev->next = meta->next;
    }
    if (meta->prev == nullptr)
    {
        _tail_mapped = meta->prev;
    }
    else
    {
        meta->next->prev = meta->prev;
    }
}

void MallocList::addToList(MallocMetadata *meta)
{
    addToAddressList(meta);
    addToSizeList(meta);
    updateValuesForMallocList(meta, ADD);
}

void MallocList::addToAddressList(MallocMetadata *meta)
{
    if (_head_by_address == nullptr)
    {
        _head_by_address = meta;
        _tail_by_address = meta;
    }
    else
    {
        MallocMetadata *curr = _head_by_address;
        while (curr != nullptr)
        {
            checkCookie(curr);
            if (curr > meta)
            {
                if (curr->prev_by_address == nullptr)
                {
                    _head_by_address = meta;
                }
                else
                {
                    curr->prev_by_address->next_by_address = meta;
                }
                meta->prev_by_address = curr->prev_by_address;
                meta->next_by_address = curr;
                curr->prev_by_address = meta;
                return;
            }
            curr = curr->next_by_address;
        }
        _tail_by_address->next_by_address = meta;
        meta->prev_by_address = _tail_by_address;
        _tail_by_address = meta;
    }
}

void MallocList::addToSizeList(MallocMetadata *meta)
{
    if (_head == nullptr)
    {
        _head = meta;
        _tail = meta;
    }
    else
    {
        MallocMetadata *curr = _head;
        while (curr != nullptr)
        {
            checkCookie(curr);
            if (curr->size > meta->size || (curr->size == meta->size && curr > meta))
            {
                if (curr->prev == nullptr)
                {
                    _head = meta;
                }
                else
                {
                    curr->prev->next = meta;
                }
                meta->prev = curr->prev;
                meta->next = curr;
                curr->prev = meta;
                return;
            }
            curr = curr->next;
        }
        _tail->next = meta;
        meta->prev = _tail;
        _tail = meta;
    }
}

void MallocList::addToMappedList(MallocMetadata *meta)
{
    if (_head_mapped == nullptr)
    {
        _head_mapped = meta;
        _tail_mapped = meta;
    }
    else
    {
        MallocMetadata *curr = _tail_mapped;
        curr->next = meta;
        meta->prev = curr;
        _tail_mapped = meta;
        meta->next = nullptr;
    }
}

void *MallocList::getData(MallocMetadata *meta)
{
    if (meta == nullptr)
        return nullptr;
    return (void *)((char *)meta + sizeof(MallocMetadata));
}

MallocMetadata *MallocList::getMetadata(void *p)
{
    if (p == nullptr)
        return nullptr;
    MallocMetadata *meta = (MallocMetadata *)((char *)p - sizeof(MallocMetadata));
    checkCookie(meta);
    return meta;
}

bool MallocList::nextIsFree(MallocMetadata *meta)
{
    if (meta->next_by_address == nullptr)
        return false;
    return meta->next_by_address->is_free;
}

bool MallocList::prevIsFree(MallocMetadata *meta)
{
    if (meta->prev_by_address == nullptr)
        return false;
    return meta->prev_by_address->is_free;
}

MallocMetadata *MallocList::mergeWithNext(MallocMetadata *meta)
{
    checkCookie(meta);
    MallocMetadata *next = getNext(meta);
    if (next == nullptr)
        return meta;
    removeFromList(meta);
    checkCookie(next);
    removeFromList(next);
    meta->size += next->size + sizeof(MallocMetadata);
    addToList(meta);
    return meta;
}

MallocMetadata *MallocList::mergeWithPrev(MallocMetadata *meta)
{
    checkCookie(meta);
    MallocMetadata *prev = getPrev(meta);
    if (prev == nullptr)
        return meta;
    removeFromList(meta);
    checkCookie(prev);
    removeFromList(prev);
    prev->size += meta->size + sizeof(MallocMetadata);
    prev->is_free = meta->is_free;
    addToList(prev);
    return prev;
}

bool MallocList::lowerSumIsEnough(MallocMetadata *meta, size_t size)
{
    checkCookie(meta);
    checkCookie(meta->prev_by_address);
    return meta->size + sizeof(MallocMetadata) + meta->prev_by_address->size >= size;
}

bool MallocList::upperSumIsEnough(MallocMetadata *meta, size_t size)
{
    checkCookie(meta);
    checkCookie(meta->next_by_address);
    return meta->size + sizeof(MallocMetadata) + meta->next_by_address->size >= size;
}

bool MallocList::lowerAndUpperSumIsEnough(MallocMetadata *meta, size_t size)
{
    checkCookie(meta);
    checkCookie(meta->prev_by_address);
    checkCookie(meta->next_by_address);
    return meta->size + 2 * sizeof(MallocMetadata) + meta->prev_by_address->size + meta->next_by_address->size >= size;
}

bool MallocList::isWilderness(MallocMetadata *meta)
{
    checkCookie(meta);
    return meta->next_by_address == nullptr;
}

void MallocList::expend(MallocMetadata *meta, size_t size)
{
    checkCookie(meta);
    if (!isWilderness(meta))
        return;
    removeFromList(meta);
    void *check = sbrk(size - meta->size);
    if (check == (void *)-1)
        return;
    meta->size = size;
    addToList(meta);
}

MallocMetadata *MallocList::getPrev(MallocMetadata *meta)
{
    checkCookie(meta);
    if (meta->prev_by_address == nullptr)
        return nullptr;
    MallocMetadata *prev = meta->prev_by_address;
    checkCookie(prev);
    return prev;
}

MallocMetadata *MallocList::getNext(MallocMetadata *meta)
{
    checkCookie(meta);
    if (meta->next_by_address == nullptr)
        return nullptr;
    MallocMetadata *next = meta->next_by_address;
    checkCookie(next);
    return next;
}

bool MallocList::higherIsWilderness(MallocMetadata *meta)
{
    checkCookie(meta);
    if (meta->next_by_address == nullptr)
        return false;
    MallocMetadata *next = meta->next_by_address;
    checkCookie(next);
    return next->next_by_address == nullptr;
}

void MallocList::makePointersToNull(MallocMetadata *meta)
{
    checkCookie(meta);
    meta->next_by_address = nullptr;
    meta->prev_by_address = nullptr;
    meta->next = nullptr;
    meta->prev = nullptr;
}

// ---------------------------------------------------------------------------

// smalloc functions ----------------------------------------------------------
void *smalloc(size_t size)
{
    if (size == 0)
        return nullptr;
    else
    {
        return malloc_list.smalloc(size);
    }
}

void *MallocList::smalloc(size_t size)
{
    if (size == 0 || size > MAX_SIZE)
        return nullptr;
    if (size >= MAP_SIZE)
    {
        return mallocMap(size);
    }
    else
    {
        return mallocList(size);
    }
}

void *MallocList::mallocMap(size_t size)
{
    void *p = mmap(nullptr, size + sizeof(MallocMetadata), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return nullptr;
    MallocMetadata *meta = (MallocMetadata *)p;
    setNewMetadata(meta, size, false, true);
    updateValuesForMallocList(meta, ADD);
    return (void *)((char *)p + sizeof(MallocMetadata));
}

void *MallocList::mallocList(size_t size)
{
    MallocMetadata *curr = findFree(size);
    if (curr != nullptr)
    {
        return mallocWithFreeBlock(curr, size);
    }
    else
    {
        return mallocWithNoFreeBlock(size);
    }
}

void *MallocList::mallocWithFreeBlock(MallocMetadata *free_block, size_t size)
{
    checkCookie(free_block);
    changeToUsed(free_block);
    if (canSplit(free_block, size))
    {
        free_block = splitBlocks(free_block, size);
        return getData(free_block);
    }
    return getData(free_block);
}

void *MallocList::mallocWithNoFreeBlock(size_t size)
{
    if (_tail_by_address != nullptr && _tail_by_address->is_free)
    {
        return mallocUsingWilderness(size);
    }
    MallocMetadata *meta = (MallocMetadata *)sbrk(0);
    void *check = sbrk(size + sizeof(MallocMetadata));
    if (check == (void *)-1)
        return nullptr;
    setNewMetadata(meta, size, false, false);
    addToList(meta);
    return getData(meta);
}

void *MallocList::mallocUsingWilderness(size_t size)
{
    MallocMetadata *meta = _tail_by_address;
    checkCookie(meta);
    changeToUsed(meta);
    expend(meta, size);
    return getData(meta);
}

// ---------------------------------------------------------------------------
// scalloc functions ----------------------------------------------------------
void *scalloc(size_t num, size_t size)
{
    if (num == 0 || size == 0)
        return nullptr;
    else
    {
        return malloc_list.scalloc(num, size);
    }
}

void *MallocList::scalloc(size_t num, size_t size)
{
    if (num == 0 || size == 0 || num * size > MAX_SIZE)
        return nullptr;
    void *p = smalloc(num * size);
    if (p == nullptr)
        return nullptr;
    memset(p, 0, num * size);
    return p;
}
// ---------------------------------------------------------------------------
// sfree functions ------------------------------------------------------------
void sfree(void *p)
{
    if (p == nullptr)
        return;
    malloc_list.sfree(p);
}

void MallocList::sfree(void *p)
{
    MallocMetadata *meta = getMetadata(p);
    if (meta == nullptr)
        return;
    checkCookie(meta);
    if (meta->is_mapped)
    {
        freeMap(meta);
    }
    else
    {
        freeList(meta);
    }
}

void MallocList::freeMap(MallocMetadata *meta)
{
    if (meta == nullptr)
        return;
    if (meta->is_free)
    {
        return;
    }
    _list_num_allocated_blocks--;
    _list_num_allocated_bytes -= meta->size;
    _list_num_meta_data_bytes -= sizeof(MallocMetadata);
    munmap(meta, meta->size + sizeof(MallocMetadata));
}

void MallocList::freeList(MallocMetadata *meta)
{
    if (meta == nullptr || meta->is_free)
        return;
    // updateValuesForMallocList(meta, REMOVE);
    changeToFree(meta);
    if (nextIsFree(meta))
    {
        meta = mergeWithNext(meta);
    }
    if (prevIsFree(meta))
    {
        meta = mergeWithPrev(meta);
    }
}
//--------------------------------------------------------------------------
// srealloc functions --------------------------------------------------------

void *srealloc(void *oldp, size_t size)
{
    if (size == 0)
    {
        sfree(oldp);
        return nullptr;
    }
    if (oldp == nullptr)
    {
        return smalloc(size);
    }
    return malloc_list.srealloc(oldp, size);
}

void *MallocList::srealloc(void *oldp, size_t size)
{
    MallocMetadata *meta = getMetadata(oldp);
    if (meta == nullptr)
        return nullptr;
    if (meta->is_mapped)
    {
        return reallocMap(meta, size);
    }
    else
    {
        return reallocList(meta, size);
    }
}

void *MallocList::reallocMap(MallocMetadata *meta, size_t size)
{
    if (meta == nullptr)
        return nullptr;
    if (size < MAP_SIZE)
    {
        return reallocMapToSmall(meta, size);
    }
    if (meta->size >= size)
    {
        return getData(meta);
    }
    void *p = smalloc(size);
    if (p == nullptr)
        return nullptr;
    memcpy(p, getData(meta), meta->size);
    sfree(getData(meta));
    return p;
}

void *MallocList::reallocList(MallocMetadata *meta, size_t size)
{
    if (meta->size >= size)
    {
        if (canSplit(meta, size))
        {
            meta = splitBlocks(meta, size);
        }
        return getData(meta);
    }
    if (prevIsFree(meta) && lowerSumIsEnough(meta, size))
    {
        return reallocLower(meta, size);
    }
    if (isWilderness(meta))
    {
        return reallocWilderness(meta, size);
    }
    if (nextIsFree(meta) && upperSumIsEnough(meta, size))
    {
        return reallocUpper(meta, size);
    }
    if (prevIsFree(meta) && nextIsFree(meta) && lowerAndUpperSumIsEnough(meta, size))
    {
        return reallocLowerAndUpper(meta, size);
    }
    if (higherIsWilderness(meta) && nextIsFree(meta))
    {
        if (prevIsFree(meta))
        {
            return reallocBothHigherIsWilderness(meta, size);
        }
        else
        {
            return reallocHigherIsWilderness(meta, size);
        }
    }
    else
    {
        return useMallocForRealloc(meta, size);
    }
}

void *MallocList::reallocLower(MallocMetadata *meta, size_t size)
{
    MallocMetadata *prev = mergeWithPrev(meta);
    memmove(getData(prev), getData(meta), meta->size);
    if (canSplit(prev, size))
    {
        prev = splitBlocks(prev, size);
    }
    return getData(prev);
}

void *MallocList::reallocUpper(MallocMetadata *meta, size_t size)
{
    MallocMetadata *next = mergeWithNext(meta);
    memmove(getData(meta), getData(next), next->size);
    if (canSplit(next, size))
    {
        next = splitBlocks(next, size);
    }
    return getData(next);
}

void *MallocList::reallocWilderness(MallocMetadata *meta, size_t size)
{
    if (prevIsFree(meta))
    {
        MallocMetadata *prev = mergeWithPrev(meta);
        expend(prev, size);
        memmove(getData(prev), getData(meta), meta->size);
        return getData(prev);
    }
    expend(meta, size);
    memmove(getData(meta), getData(meta), meta->size);
    return getData(meta);
}

void *MallocList::reallocLowerAndUpper(MallocMetadata *meta, size_t size)
{
    MallocMetadata *prev = mergeWithPrev(meta);
    MallocMetadata *next = mergeWithNext(prev);
    memmove(getData(next), getData(meta), meta->size);
    if (canSplit(next, size))
    {
        next = splitBlocks(next, size);
    }
    return getData(next);
}

void *MallocList::reallocBothHigherIsWilderness(MallocMetadata *meta, size_t size)
{
    MallocMetadata *prev = mergeWithPrev(meta);
    MallocMetadata *next = mergeWithNext(prev);
    memmove(getData(next), getData(meta), meta->size);
    if (!isWilderness(next))
    {
        perror("marge with next failed");
    }
    expend(next, size);
    return getData(next);
}

void *MallocList::reallocHigherIsWilderness(MallocMetadata *meta, size_t size)
{
    MallocMetadata *next = mergeWithNext(meta);
    memmove(getData(meta), getData(next), next->size);
    if (!isWilderness(next))
    {
        perror("marge with next failed");
    }
    expend(next, size);
    return getData(next);
}

void *MallocList::useMallocForRealloc(MallocMetadata *meta, size_t size)
{
    void *p = smalloc(size);
    if (p == nullptr)
        return nullptr;
    memcpy(p, getData(meta), meta->size);
    sfree(getData(meta));
    return p;
}

void *MallocList::reallocMapToSmall(MallocMetadata *meta, size_t size)
{
    void *p = smalloc(size);
    if (p == nullptr)
        return nullptr;
    memcpy(p, getData(meta), size);
    sfree(getData(meta));
    return p;
}

// ---------------------------------------------------------------------------
size_t _num_free_blocks()
{
    return malloc_list.getNumFreeBlocks();
}
size_t _num_free_bytes()
{
    return malloc_list.getNumFreeBytes();
}
size_t _num_allocated_blocks()
{
    return malloc_list.getNumAllocatedBlocks();
}
size_t _num_allocated_bytes()
{
    return malloc_list.getNumAllocatedBytes();
}
size_t _num_meta_data_bytes()
{
    return malloc_list.getNumMetaDataBytes();
}
size_t _size_meta_data()
{
    return sizeof(MallocMetadata);
}