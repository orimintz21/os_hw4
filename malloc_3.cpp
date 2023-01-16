#include <unistd.h>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <sys/mman.h>

#define MAX_SIZE 1000000000
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
private:
    MallocList() : _head(nullptr), _tail(nullptr), _head_by_address(nullptr), _tail_by_address(nullptr),
                   _cookie(0), _list_num_free_blocks(0), _list_num_free_bytes(0),
                   _list_num_allocated_blocks(0), _list_num_allocated_bytes(0), _list_num_meta_data_bytes(0)
    {
        std::srand(std::time(nullptr)); // use current time as seed for random generator
        _cookie = std::rand();
    }
    static MallocList &_instance;
    MallocMetadata *_head;
    MallocMetadata *_tail;
    MallocMetadata *_head_by_address;
    MallocMetadata *_tail_by_address;
    int _cookie;
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
    void addNode(MallocMetadata *node);
    void addNodeToAddressList(MallocMetadata *node);
    void addNodeToSizeList(MallocMetadata *node);
    void removeNode(MallocMetadata *node);
    void removeNodeFromAddressList(MallocMetadata *node);
    void removeNodeFromSizeList(MallocMetadata *node);
    MallocMetadata *findData(void *data);
    MallocMetadata *findFree(size_t size);
    void margeFree(MallocMetadata *node);

    void checkCookie(MallocMetadata *node);

    void *mallocData(const size_t size);
    void *callocData(const size_t num, const size_t size);
    void freeData(void *data);
    void *reallocData(void *data, const size_t size);

    // Todo:
    MallocMetadata *getNextNode(MallocMetadata *node);
    MallocMetadata *getPrevNode(MallocMetadata *node);
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

void nullefyNode(MallocMetadata *node)
{
    node->next = NULL;
    node->prev = NULL;
    node->next_by_address = NULL;
    node->prev_by_address = NULL;
}

void MallocList::addNodeToAddressList(MallocMetadata *node)
{
    MallocMetadata *top = _tail_by_address;
    top->next_by_address = node;
    node->prev_by_address = top;
    _tail_by_address = node;
}

void MallocList::addNodeToSizeList(MallocMetadata *node)
{
    MallocMetadata *curr = _head;
    while (curr != NULL)
    {
        if (curr->size >= node->size)
        {
            if (curr->size > node->size || curr > node)
            {
                if (curr == _head)
                {
                    _head = node;
                    node->next = curr;
                    curr->prev = node;
                }
                else
                {
                    node->next = curr;
                    node->prev = curr->prev;
                    curr->prev->next = node;
                    curr->prev = node;
                }
            }
            else
            {
                if (curr == _tail)
                {
                    _tail = node;
                    node->prev = curr;
                    curr->next = node;
                }
                else
                {
                    node->next = curr->next;
                    node->prev = curr;
                    curr->next->prev = node;
                    curr->next = node;
                }
            }
            return;
        }
    }
    _tail->next = node;
    node->prev = _tail;
    _tail = node;

    return;
}

// asserts that the node is allocated
void MallocList::addNode(MallocMetadata *node)
{
    nullefyNode(node);
    if (node->is_free)
    {
        _list_num_free_blocks++;
        _list_num_free_bytes += node->size;
    }

    if (_head == NULL)
    {
        _head = node;
        _head_by_address = node;
        _tail = node;
        _tail_by_address = node;
        _list_num_free_blocks = 0;
        _list_num_free_bytes = 0;
        _list_num_allocated_blocks = 1;
        _list_num_allocated_bytes = node->size;
        _list_num_meta_data_bytes = _size_meta_data();
    }
    else
    {
        addNodeToAddressList(node);
        addNodeToSizeList(node);
        _list_num_allocated_blocks++;
        _list_num_allocated_bytes += node->size;
        _list_num_meta_data_bytes += _size_meta_data();
    }
}

void MallocList::checkCookie(MallocMetadata *node)
{
    if (node->_cookie != this->_cookie)
    {
        exit(0xdeadbeef);
    }
}

void MallocList::removeNodeFromAddressList(MallocMetadata *node)
{
    if (node == _head_by_address)
    {
        _head_by_address = node->next_by_address;
        if (_head_by_address != NULL)
        {
            _head_by_address->prev_by_address = NULL;
        }
    }
    else if (node == _tail_by_address)
    {
        _tail_by_address = node->prev_by_address;
        if (_tail_by_address != NULL)
        {
            _tail_by_address->next_by_address = NULL;
        }
    }
    else
    {
        node->prev_by_address->next_by_address = node->next_by_address;
        node->next_by_address->prev_by_address = node->prev_by_address;
    }
}

void MallocList::removeNodeFromSizeList(MallocMetadata *node)
{
    if (node == _head)
    {
        _head = node->next;
        if (_head != NULL)
        {
            _head->prev = NULL;
        }
    }
    else if (node == _tail)
    {
        _tail = node->prev;
        if (_tail != NULL)
        {
            _tail->next = NULL;
        }
    }
    else
    {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }
}

void MallocList::removeNode(MallocMetadata *node)
{
    removeNodeFromAddressList(node);
    removeNodeFromSizeList(node);

    _list_num_allocated_blocks--;
    _list_num_allocated_bytes -= node->size;
    if (node->is_free)
    {
        _list_num_free_blocks--;
        _list_num_free_bytes -= node->size;
    }
    _list_num_meta_data_bytes -= _size_meta_data();
}

MallocMetadata *MallocList::findData(void *data)
{
    if (data == NULL)
    {
        return NULL;
    }
    MallocMetadata *curr = (MallocMetadata *)((char *)data - _size_meta_data());
    checkCookie(curr);
    return curr;
}

MallocMetadata *MallocList::findFree(size_t size)
{
    MallocMetadata *curr = _head;
    while (curr != NULL)
    {
        checkCookie(curr);
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
    if (size == 0)
    {
        return NULL;
    }
    if (size >= 128 * 1024)
    {
        MallocMetadata *new_data = (MallocMetadata *)mmap(NULL, size + _size_meta_data(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    MallocMetadata *curr = findFree(size);
    // if there is a free block that is big enough
    if (curr != nullptr)
    {
        checkCookie(curr);

        if (curr->size >= size + 128 + _size_meta_data())
        {
            removeNode(curr);
            MallocMetadata *new_node = (MallocMetadata *)((char *)curr + _size_meta_data() + size);
            new_node->size = curr->size - size - _size_meta_data();
            new_node->is_free = true;
            new_node->is_mapped = false;
            new_node->_cookie = this->_cookie;

            addNode(new_node);
            curr->size = size;
            curr->is_free = false;
            curr->is_mapped = false;
            curr->_cookie = this->_cookie;
            addNode(curr);
            return (void *)(curr + 1);
        }
        else
        {
            curr->is_free = false;
            curr->_cookie = this->_cookie;
            curr->is_mapped = false;
            _list_num_free_blocks--;
            _list_num_free_bytes -= curr->size;
            return (void *)(curr + 1);
        }
    }
    else
    {
        if (_tail_by_address != NULL && _tail_by_address->is_free)
        {
            checkCookie(_tail_by_address);
            MallocMetadata *temp = _tail_by_address;
            removeNode(temp);
            int old_size = temp->size;
            void *check = sbrk(size - old_size);
            if (check == (void *)-1)
            {
                return NULL;
            }
            temp->size = size;
            temp->is_free = false;
            temp->is_mapped = false;
            temp->_cookie = this->_cookie;
            addNode(temp);
            return (void *)(temp + 1);
        }

        MallocMetadata *new_node = (MallocMetadata *)sbrk(size + _size_meta_data());
        if (new_node == (void *)-1)
        {
            return NULL;
        }
        new_node->size = size;
        new_node->is_free = false;
        new_node->is_mapped = false;
        new_node->_cookie = this->_cookie;
        addNode(new_node);
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
        checkCookie(curr);
        curr->is_free = true;
        _list_num_free_blocks++;
        _list_num_free_bytes += curr->size;
        margeFree(curr);
    }
}

void MallocList::margeFree(MallocMetadata *node)
{
    if (node == NULL)
    {
        return;
    }
    if (node->next_by_address != nullptr && node->next_by_address->is_free)
    {
        MallocMetadata *temp = node->next_by_address;
        checkCookie(temp);
        removeNode(temp);
        removeNode(node);
        node->size += temp->size + _size_meta_data();
        addNode(node);
    }
    if (node->prev_by_address != nullptr && node->prev_by_address->is_free)
    {
        MallocMetadata *temp = node->prev_by_address;
        checkCookie(temp);
        removeNode(temp);
        removeNode(node);
        temp->size += node->size + _size_meta_data();
        addNode(temp);
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
