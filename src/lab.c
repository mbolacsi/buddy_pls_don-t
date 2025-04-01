#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
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
        raise(SIGKILL);          \
    } while (0)

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
     // The expression (UINT64_C(1) << kval) shifts 1 as a 64-bit constant.
     while ((UINT64_C(1) << kval) < (uint64_t)bytes) {
         kval++;
     }
     
     return (size_t)kval;
 }

  /**
   * Find the buddy of a given pointer and kval relative to the base address we got from mmap
   * @param pool The memory pool to work on (needed for the base addresses)
   * @param buddy The memory block that we want to find the buddy for
   * @return A pointer to the buddy
   */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
        if (!pool || !buddy) {
            errno = ENOMEM;  // Set errno to indicate memory allocation failure
            return NULL;
        }


}

  /**
   * Allocates a block of size bytes of memory, returning a pointer to
   * the beginning of the block. The content of the newly allocated block
   * of memory is not initialized, remaining with indeterminate values.
   * @param pool The memory pool to alloc from
   * @param size The size of the user requested memory block in bytes
   * @return A pointer to the memory block
   */
void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    if (size == 0 || pool == NULL){
        errno = ENOMEM;  // Set errno to indicate memory allocation failure
        return NULL;
    }

    //get the kval for the requested size with enough room for the tag and kval fields
    size_t kval = btok(size) + 1; // Add 1 to account for header

    //Find a block
    // Find the smallest available block with order j where kval <= j <= max_k.
    // Validation check, ensure there is some free memory
    for (kval <= pool->max_k; kval++) {
        if (pool->avail[j]->next != pool->avail[j]) {
            break;
        }
    }

    //There was not enough memory to satisfy the request thus we need to set error and return NULL
    // Validation check, ensure the requested memory isn't more than 
    if(j > pool->max_k){
        errno = ENOMEM;  // Set errno to indicate memory allocation failure
        return NULL;
    }

    //Remove from list;
    struck block *L = pool->avail[j].next;
    P = L->next;
    pool->avail[j].next = P;
    L->prev = &pool->avail[k];    
    L->tag = 0; // Mark the block as allocated

    // Split the block until reaching the desired size.
    while (j >kval){
        j--;

        // Split the block L into two buddies.
        struct block *R = (struct block *)((char *)L + (UINT64_C(1) << j));

        // Initialize the right buddy block.
        R->tag = 1;       // mark as free
        R->kval = j;
    
        // Insert R into the free list for order j.
        R->next =  R->prev = &pool->avail[j];
        pool->avail[j].next = pool->avail[j].prev = R;
    }

    // Return a pointer to the allocated block (adjust pointer if header is not user data).
    return (void *)L;
}

  /**
   * A block of memory previously allocated by a call to malloc,
   * calloc or realloc is deallocated, making it available again
   * for further allocations.
   *
   * If ptr does not point to a block of memory allocated with
   * the above functions, it causes undefined behavior.
   *
   * If ptr is a null pointer, the function does nothing.
   * Notice that this function does not change the value of ptr itself,
   * hence it still points to the same (now invalid) location.
   *
   * @param pool The memory pool
   * @param ptr Pointer to the memory block to free
   */
void buddy_free(struct buddy_pool *pool, void *ptr)
{

}

  /**
   * Initialize a new memory pool using the buddy algorithm. Internally,
   * this function uses mmap to get a block of memory to manage so should be
   * portable to any system that implements mmap. This function will round
   * up to the nearest power of two. So if the user requests 503MiB
   * it will be rounded up to 512MiB.
   *
   * Note that if a 0 is passed as an argument then it initializes
   * the memory pool to be of the default size of DEFAULT_K. If the caller
   * specifies an unreasonably small size, then the buddy system may
   * not be able to satisfy any requests.
   *
   * NOTE: Memory pools returned by this function can not be intermingled.
   * Calling buddy_malloc with pool A and then calling buddy_free with
   * pool B will result in undefined behavior.
   *
   * @param size The size of the pool in bytes.
   * @param pool A pointer to the pool to initialize
   */
void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    //make sure pool struct is cleared out
    memset(pool,0,sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    //Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                               /*addr to map to*/
        pool->numbytes,                     /*length*/
        PROT_READ | PROT_WRITE,             /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS,        /*flags*/
        -1,                                 /*fd -1 when using MAP_ANONYMOUS*/
        0                                   /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    //Set all blocks to empty. We are using circular lists so the first elements just point
    //to an available block. Thus the tag, and kval feild are unused burning a small bit of
    //memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    //Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

  /**
   * Inverse of buddy_init.
   *
   * Notice that this function does not change the value of pool itself,
   * hence it still points to the same (now invalid) location.
   *
   * @param pool The memory pool to destroy
   */
void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    //Zero out the array so it can be reused it needed
    memset(pool,0,sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
static void printb(unsigned long int b)
{
     size_t bits = sizeof(b) * 8;
     unsigned long int curr = UINT64_C(1) << (bits - 1);
     for (size_t i = 0; i < bits; i++)
     {
          if (b & curr)
          {
               printf("1");
          }
          else
          {
               printf("0");
          }
          curr >>= 1L;
     }
}
