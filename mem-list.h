#include <list.h>

typedef struct __pool_def pool_t;

typedef struct {
    struct list_head list;
    int size;
    void *mem;
} mem_t;

struct __pool_def {
    struct list_head free_list;
    struct list_head used_list;
    void *mem;
    void *mem_list;
    unsigned int free_size;
    unsigned int used_size;
//    int (*calloc)(pool_t *pool, int n, int size);
    int (*add_mem)(pool_t *pool, void *mem, int size);
    void (*del_mem)(pool_t *pool, mem_t *m);
    void (*del_all)(pool_t *pool);
};

void init_pool(pool_t *pool, int n, int size);
void free_pool(pool_t *pool);
