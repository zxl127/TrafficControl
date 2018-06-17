#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <mem-list.h>

static int pool_add_mem(pool_t *pool, void *mem, int size)
{
    mem_t *m;

    if(list_empty(&pool->free_list))
        return false;
    m = list_first_entry(&pool->free_list, mem_t, list);
    if(size <= m->size) {
        memcpy(m->mem, mem, size);
        list_del(&m->list);
        list_add_tail(&m->list, &pool->used_list);
        pool->free_size--;
        pool->used_size++;
        return true;
    } else {
        return false;
    }
}

static void pool_del_mem(pool_t *pool, mem_t *m)
{
//    mem_t *mem, *tmp;

//    list_for_each_entry_safe(mem, tmp, &pool->used_list, list) {
//        if(m == mem) {
            list_del(&m->list);
            list_add_tail(&m->list, &pool->free_list);
            pool->free_size++;
            pool->used_size--;
//        }
//    }
}

static void pool_del_all(pool_t *pool)
{
    mem_t *m, *tmp;

    list_for_each_entry_safe(m, tmp, &pool->used_list, list) {
        list_del(&m->list);
        list_add_tail(&m->list, &pool->free_list);
        pool->free_size++;
    }
    pool->used_size = 0;
}

static int pool_calloc(pool_t *pool, int n, int size)
{
    int i;
    void *mem;
    mem_t *m;

    m = calloc(n, sizeof(mem_t));
    if(m == NULL)
        return false;

    mem = calloc(n, size);
    if(mem == NULL) {
        free(m);
        return false;
    }
    pool->mem = mem;
    pool->mem_list = m;
    for(i = 0; i < n; ++i) {
        m->mem = mem + i * size;
        m->size = size;
        list_add_tail(&m->list, &pool->free_list);
        ++m;
    }
    pool->free_size = n;

    return true;
}

void init_pool(pool_t *pool, int n, int size)
{
    pool->mem = 0;
    pool->mem_list = 0;
    pool->free_size = 0;
    pool->used_size = 0;
//    pool->calloc = pool_calloc;
    pool->add_mem = pool_add_mem;
    pool->del_all = pool_del_all;
    pool->del_mem = pool_del_mem;
    INIT_LIST_HEAD(&pool->free_list);
    INIT_LIST_HEAD(&pool->used_list);
    pool_calloc(pool, n, size);
}

void free_pool(pool_t *pool)
{
    list_del(&pool->free_list);
    list_del(&pool->used_list);
    free(pool->mem);
    free(pool->mem_list);
}
