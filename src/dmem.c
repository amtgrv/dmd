/*
 * Copyright (c) 2017, Amit Gaurav
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the project nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY AMIT GAURAV ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AMIT GAURAV BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pthread.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>

/* Declare glibc libraries. */
extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t length, size_t size);
extern void *__libc_realloc(void *addr, size_t size);
extern void *__libc_memalign(size_t alignment, size_t size);
extern void __libc_free(void *addr);

/* Current state of memory debugger. */
typedef enum dmem_state_t
{
    DMEM_UNINITIALIZED = 0,
    DMEM_ENABLED,
    DMEM_DISABLED
} dmem_state;

/* Current state of memory tracking in debugger. */
typedef enum dmem_tracking_t
{
    DMEM_TRACKING_DISABLED = 1,
    DMEM_TRACKING_ENABLED
} dmem_tracking;

/* Initialize global variables. */
static int g_dmem_tag = 0;
static int g_dmem_state = DMEM_UNINITIALIZED;
static int g_dmem_track = DMEM_TRACKING_DISABLED;
static pthread_mutex_t dlock = PTHREAD_MUTEX_INITIALIZER;

/* The header. */
typedef struct dmem_header_t
{
    char protection[8];    // MAGIC BYTES
    char unused[8];        // Unused as of now
    size_t alignment;      // Alignment (for memalign)
    size_t size;           // Size of allocated user memory
} dmem_header;

/* The footer. */
typedef struct dmem_footer_t
{
    char protection[8];    // MAGIC BYTES
    size_t memcheck;       // Flag to track memory allocations
    size_t tag;            // Return address of parent caller
    void *caller;          // Return address of allocation
} dmem_footer;

#define MAGIC_START	"OKBOKBOK"
#define MAGIC_END	"OKEOKEOK"
#define MAGIC_ALIGN	"MEMALIGN"

void dmem_init()
{
    if (g_dmem_state == DMEM_UNINITIALIZED) {
        pthread_mutex_lock(&dlock);
        if (g_dmem_state == DMEM_UNINITIALIZED) {
            /* Set access based on file policy, as of now. */
            if (access("/tmp/.dmem_enable", R_OK) == 0) {
                g_dmem_state = DMEM_ENABLED;
            }
            else {
                g_dmem_state = DMEM_DISABLED;
            }

            /* Set memory tracking based on file policy. */
            if (access("/tmp/.dmem_tracking", R_OK) == 0) {
                g_dmem_track = DMEM_TRACKING_ENABLED;
            }
            else {
                g_dmem_track = DMEM_TRACKING_DISABLED;
            }
        }
        pthread_mutex_unlock(&dlock);
    }
}

/* Wrap the malloc subroutine. */
void *malloc(size_t size)
{
    dmem_init();

    if (g_dmem_state == DMEM_DISABLED) return __libc_malloc(size);

    int *p = NULL;

    /* Unlike some of the systems, zero size requests returns NULL. */
    if (size == 0) return NULL;

    /* Get the estimated total size. */
    size_t malloc_size = size +
                         sizeof(dmem_header) +
                         sizeof(dmem_footer);

    /* TODO: Should use dlsym to get glibc malloc. */
    char *start_buffer = __libc_malloc(malloc_size);
    if (!start_buffer) return NULL;

    /* Copy header information. */
    dmem_header *header = (dmem_header *)start_buffer;
    memcpy(header->protection, MAGIC_START, 8);
    header->unused[0] = '\0';
    header->alignment = 0;
    header->size = size;

    /* Copy footer information. */
    char *end_buffer = start_buffer + size + sizeof(dmem_header);
    dmem_footer *footer = (dmem_footer *)end_buffer;
    memcpy(footer->protection, MAGIC_END, 8);

    /* Populate return address if tracking is enabled. */
    if (g_dmem_track == DMEM_TRACKING_ENABLED) {
        footer->memcheck = size;
        footer->tag = g_dmem_tag;
        void *addr = __builtin_return_address(0);
        memcpy(&footer->caller,
               &addr,
               sizeof(void *));
    }
    else {
        footer->memcheck = 0;
    }

    /* Return user pointer. */
    return (char *)(start_buffer) + sizeof(dmem_header);
}

/* Wrap free subroutine. */
void free(void *addr)
{
    if (g_dmem_state == DMEM_DISABLED) {
        __libc_free(addr);
        return;
    }

    if (addr == NULL) return;

    char *buffer = (char *)addr;
    int *p = NULL;

    /* Unwind the start address from user pointer. */
    char *start_buffer = buffer - sizeof(dmem_header);
    if (memcmp(start_buffer, MAGIC_START, 8) == 0) {
        dmem_header *header = (dmem_header *)start_buffer;

        char *end_buffer = start_buffer + header->size + sizeof(dmem_header);
        if (memcmp(end_buffer, MAGIC_END, 8) != 0) {
            /* assert deliberately. */
            /* TODO: Use a better option. */
            *p = 1;
        }

        /* Check if the memory was allocated through memalign. */
        if (header->alignment > sizeof(dmem_header)) {
            char *alloc_address = buffer - header->alignment;
            if (memcmp(alloc_address, MAGIC_ALIGN, 8) != 0) {
                /* something bad happened. */
                *p = 1;
            }
            start_buffer = alloc_address;
        }

        memset(start_buffer, 0, 8);
        memset(end_buffer, 0, 8);
        __libc_free(start_buffer);
    }
    else {
        /* Not allocated using our malloc OR could have been corrupted. */
        *p = 1;
    }
}

/* Wrap calloc subroutine. */
void *calloc(size_t length, size_t size)
{

    /* Redirect to malloc. */
    char *buffer = malloc(length * size);
    if (!buffer) return NULL;

    /* Update the return address in calloc. */
    if (g_dmem_track == DMEM_TRACKING_ENABLED) {
        char *end_buffer = buffer + (length * size);
        dmem_footer *footer = (dmem_footer *)end_buffer;
        void *addr = __builtin_return_address(0);
        memcpy(&footer->caller,
               &addr,
               sizeof(void *));
    }

    return memset(buffer, 0, length * size);
}

size_t dmem_min(size_t size1, size_t size2)
{
    return (size1 < size2)? size1 : size2;
}

/* Wrap realloc subroutine. */
void *realloc(void *addr, size_t size)
{
    /* Behaves same if addr is NULL. */
    if (addr == NULL) {
        addr = malloc(size);
        return addr;
    }

    int *p = NULL;
    char *buffer = (char*)addr;
    char *start_buffer = buffer - sizeof(dmem_header);
    char *new_buffer = NULL;

    if (memcmp(start_buffer, MAGIC_START, 8) == 0) {
        dmem_header *header = (dmem_header *)start_buffer;
        char *end_buffer = buffer + header->size;

        if (memcmp(end_buffer, MAGIC_END, 8) != 0) {
            /* Someone trespassed. */
            *p = 1;
        }

        memset(start_buffer, 0, 8);
        memset(end_buffer, 0, 8);

        /* Allocate new buffer and copy existing memory. */
        new_buffer = malloc(size);
        memcpy(new_buffer, buffer, dmem_min(size, header->size));
        __libc_free(start_buffer);
    }
    else {
        char *temp_buffer = __libc_realloc(addr, size);
        new_buffer = malloc(size);
        memcpy(new_buffer, temp_buffer, size);
        __libc_free(temp_buffer);
    }

    /* Update return address. */
    if (g_dmem_track == DMEM_TRACKING_ENABLED) {
        char *end_buffer = new_buffer + size;
        dmem_footer *footer = (dmem_footer *)end_buffer;
        void *addr = __builtin_return_address(0);
        memcpy(&footer->caller,
               &addr,
               sizeof(void *));
    }

    return (void *)(new_buffer);
}

/* Wrap memalign subroutine. */
void *memalign(size_t alignment, size_t size)
{
    dmem_init();

    if (g_dmem_state == DMEM_DISABLED) return __libc_memalign(alignment, size);

    int *p = NULL;
    if (size == 0) return NULL;

    /* Get a safe side alignment. */
    size_t p_bytes = (alignment > sizeof(dmem_header))?
                      alignment : sizeof(dmem_header);

    size_t malloc_size = size + p_bytes + sizeof(dmem_footer); 

    char *start_buffer = __libc_memalign(alignment, malloc_size);
    if (!start_buffer) return NULL;

    /* Add magic bytes to start buffer too */
    memcpy(start_buffer, MAGIC_ALIGN, 8);

    dmem_header *header = (dmem_header *)(start_buffer +
                                  p_bytes - sizeof(dmem_header));
    memcpy(header->protection, MAGIC_START, 8);
    header->unused[0] = '\0';
    header->alignment = p_bytes; /* Set new alignment. */
    header->size = size;

    char *end_buffer = start_buffer + p_bytes + size;
    dmem_footer *footer = (dmem_footer *)end_buffer;
    memcpy(footer->protection, MAGIC_END, 8);

    /* Update return address. */
    if (g_dmem_track == DMEM_TRACKING_ENABLED) {
        footer->memcheck = size;
        footer->tag = g_dmem_tag;
        void *addr = __builtin_return_address(0);
        memcpy(&footer->caller,
               &addr,
               sizeof(void *));
    } else {
        footer->memcheck = 0;
    }

    return (char *)(start_buffer) + p_bytes;
}

