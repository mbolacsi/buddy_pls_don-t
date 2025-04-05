#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);           \
    } while (0)

#define DEBUG

// Debugging helper to print memory block status
#ifdef DEBUG
#define dbg_printf(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define dbg_printf(fmt, ...) 
#endif

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes)
{
    int kval = 0;
    // Find the smallest power k such that 2^k is greater than or equal to bytes.
    while ((UINT64_C(1) << kval) < (uint64_t)bytes) {
        kval++;
    }
    return (size_t)kval;
}

/**
 * Find the buddy of a given pointer and kval relative to the base address
 * @param pool The memory pool to work on (needed for the base addresses)
 * @param block The memory block that we want to find the buddy for
 * @return A pointer to the buddy
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block)
{
    if (!pool || !block) {
        errno = ENOMEM;
        return NULL;
    }

    uintptr_t base_addr = (uintptr_t)pool->base;
    uintptr_t block_addr = (uintptr_t)block;
    size_t block_size = (UINT64_C(1) << block->kval); 

    uintptr_t buddy_offset = (block_addr - base_addr) ^ block_size;
    uintptr_t buddy_addr = base_addr + buddy_offset;

    dbg_printf("Buddy calculation: base_addr=%" PRIuPTR ", block_addr=%" PRIuPTR ", buddy_addr=%" PRIuPTR "\n", base_addr, block_addr, buddy_addr);

    return (struct avail *)buddy_addr;
}

/**
 * Allocates a block of size bytes of memory, returning a pointer to
 * the beginning of the block.
 */
 void *buddy_malloc(struct buddy_pool *pool, size_t size)
 {
     if (size == 0 || pool == NULL) {
         errno = ENOMEM;  
         return NULL;
     }
 
     // Include the avail struct overhead in the size
     size_t kval = btok(size + sizeof(struct avail));
 
     if(kval < SMALLEST_K){
         kval = SMALLEST_K;
     }
 
     size_t j = kval;
     bool block_found = false;
 
     // Keep searching up through free list until you either find a suitable block, or you've checked every free list up to the largest known one.
     while (j <= pool->avail[0].kval) {
         if (pool->avail[j].next != &pool->avail[j]) {
             block_found = true;
             break;
         }
         j++;
     }
 
     if (!block_found) {
         errno = ENOMEM;
         return NULL;
     }
 
     // Remove the block from the free list at level j
     struct avail *block = pool->avail[j].next;
     block->prev->next = block->next;
     block->next->prev = block->prev;
     block->tag = BLOCK_RESERVED; // Mark as allocated
 
     // Split blocks down to the required size
     while (j > kval) {
         j--;
         // Use buddy_calc to find the buddy block 
         struct avail *buddy = buddy_calc(pool, block);
 
         buddy->tag = BLOCK_AVAIL;
         buddy->kval = j;
 
         // Insert buddy into the free list
         buddy->next = pool->avail[j].next;
         buddy->prev = &pool->avail[j];
         pool->avail[j].next->prev = buddy;
         pool->avail[j].next = buddy;
     }
 
     return (void *)block;
 }
 

/**
 * A block of memory previously allocated by a call to malloc,
 * calloc or realloc is deallocated, making it available again
 * for further allocations.
 *
 * @param pool The memory pool
 * @param ptr Pointer to the memory block to free
 */
 void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (!pool || !ptr)
        return;

    struct avail *block = (struct avail *)ptr;
    uint64_t kval = block->kval;

    dbg_printf("buddy_free: Freeing block at kval=%zu\n", kval);

    // Mark the block as free.
    block->tag = BLOCK_AVAIL;

    // Try to merge with its buddy
    while (kval < MAX_K) {
        struct avail *buddy = buddy_calc(pool, block);

        // Guard: if buddy_calc returns the same block, break out.
        if (buddy == block)
            break;

        // Only merge if buddy is free and has the same order
        if (!(buddy->tag == BLOCK_AVAIL && buddy->kval == kval))
            break;

        // Remove buddy from its free list.
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Choose the lower address as the base block.
        if ((uintptr_t)buddy < (uintptr_t)block)
            block = buddy;

        // Increase the block order.
        kval++;
        block->kval = kval;

        dbg_printf("Merging with buddy, new kval=%zu\n", kval);
    }

    // Reinsert the block into the free list.
    block->prev = &pool->avail[kval];
    block->next = pool->avail[kval].next;
    pool->avail[kval].next->prev = block;
    pool->avail[kval].next = block;
}

/**
 * Initialize a new memory pool using the buddy algorithm
 */
void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = size == 0 ? DEFAULT_K : btok(size);
    if (kval < MIN_K) kval = MIN_K;
    if (kval > MAX_K) kval = MAX_K - 1;

    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == pool->base) {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    // Initialize free list
    for (size_t i = 0; i <= kval; i++) {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];

    dbg_printf("buddy_init: Pool initialized, base=%" PRIuPTR ", kval_m=%zu\n", (uintptr_t)pool->base, pool->kval_m);
}

/**
 * Inverse of buddy_init.
 */
void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval) {
        handle_error_and_die("buddy_destroy avail array");
    }
    memset(pool, 0, sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x
