/*
    Functions to access the memory of the target process.
 
    Copyright (C) 2006,2007,2009 Tavis Ormandy <taviso@sdf.lonestar.org>
    Copyright (C) 2009           Eli Dupree <elidupree@charter.net>
    Copyright (C) 2009,2010      WANG Lu <coolwanglu@gmail.com>
    Copyright (C) 2015           Sebastian Parschauer <s.parschauer@gmx.de>
    Copyright (C) 2017-2018      Andrea Stacchiotti <andreastacchiotti(a)gmail.com>
 
    This file is part of libscanmem.

    This library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this library.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"

/* for pread */
# ifdef _XOPEN_SOURCE
#  undef _XOPEN_SOURCE
# endif
# define _XOPEN_SOURCE 500

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>

#if HAVE_PROCESS_VM_READV
#include <sys/uio.h>
#endif

// dirty hack for FreeBSD
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#define PTRACE_ATTACH PT_ATTACH
#define PTRACE_DETACH PT_DETACH
#define PTRACE_PEEKDATA PT_READ_D
#define PTRACE_POKEDATA PT_WRITE_D
#endif

#include "common.h"
#include "value.h"
#include "scanroutines.h"
#include "scanmem.h"
#include "show_message.h"
#include "targetmem.h"
#include "interrupt.h"

/* progress handling */
#define NUM_DOTS (10)
#define NUM_SAMPLES (100)
#define MAX_PROGRESS (1.0)  /* 100% */
#if (!NUM_DOTS || !NUM_SAMPLES || NUM_SAMPLES % NUM_DOTS != 0)
#error Invalid NUM_DOTS to NUM_SAMPLES proportion!
#endif
#define SAMPLES_PER_DOT (NUM_SAMPLES / NUM_DOTS)
#define PROGRESS_PER_SAMPLE (MAX_PROGRESS / NUM_SAMPLES)

bool sm_attach(pid_t target, struct attach_state_t* attach_state)
{
    if (!sm_globals.options.no_ptrace)
    {
        int status;

        /* attach to the target application, which should cause a SIGSTOP */
        if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1L) {
            show_error("failed to attach to %d, %s\n", target, strerror(errno));
            return false;
        }

        /* wait for the SIGSTOP to take place. */
        if (waitpid(target, &status, 0) == -1 || !WIFSTOPPED(status)) {
            show_error("there was an error waiting for the target to stop.\n");
            show_info("%s\n", strerror(errno));
            return false;
        }
    }

#if HAVE_PROCMEM
    { /* open the `/proc/<pid>/mem` file */
        char mem[32];
        int fd;

        /* print the path to mem file */
        snprintf(mem, sizeof(mem), "/proc/%d/mem", target);

        /* attempt to open the file */
        if ((fd = open(mem, O_RDWR)) == -1) {
            show_error("unable to open %s.\n", mem);
            return false;
        }
        attach_state->procmem_fd = fd;
    }
#endif
    attach_state->pid = target;

    /* everything looks okay */
    return true;

}

bool sm_detach(pid_t target, struct attach_state_t* attach_state)
{
#if HAVE_PROCMEM
    if (attach_state != NULL)
    {
        /* close the mem file before detaching */
        close(attach_state->procmem_fd);
    }
#endif

    if (!sm_globals.options.no_ptrace)
    {
        /* addr is ignored on Linux, but should be 1 on FreeBSD in order to let
        * the child process continue execution where it had been interrupted */
        return ptrace(PTRACE_DETACH, target, 1, 0) == 0;
    }
    else
    {
        return true;
    }
}

/* Reads data from the target process, and places it on the `dest_buffer`
 * using either `ptrace` or `pread` on `/proc/pid/mem`.
 * The target process is not passed, but read from the static peekbuf.
 * `sm_attach()` MUST be called before this function. */
static inline size_t sm_readmemory(uint8_t *dest_buffer, const char *target_address, size_t size, struct attach_state_t* attach_state)
{
    size_t nread = 0;

#if HAVE_PROCMEM || HAVE_PROCESS_VM_READV
    do {
#if HAVE_PROCMEM
        ssize_t ret = pread(attach_state->procmem_fd, dest_buffer + nread,
                            size - nread, (unsigned long)(target_address + nread));
#elif HAVE_PROCESS_VM_READV
        struct iovec local[1];
        struct iovec remote[1];

        local[0].iov_base = dest_buffer + nread;
        local[0].iov_len = size - nread;
        remote[0].iov_base = target_address + nread;
        remote[0].iov_len = size - nread;

        ssize_t ret = process_vm_readv(attach_state->pid, local, 1, remote, 1, 0);
#endif
        if (ret == -1) {
            /* we can't read further, report what was read */
            return nread;
        }
        else {
            /* some data was read */
            nread += ret;
        }
    } while (nread < size);
#else
    /* Read the memory with `ptrace()`: the API specifies that `ptrace()` returns a `long`, which
     * is the size of a word for the current architecture, so this section will deal in `long`s */
    assert(size % sizeof(long) == 0);
    errno = 0;
    for (nread = 0; nread < size; nread += sizeof(long)) {
        const char *ptrace_address = target_address + nread;
        long ptraced_long = ptrace(PTRACE_PEEKDATA, attach_state->pid, ptrace_address, NULL);

        /* check if ptrace() succeeded */
        if (UNLIKELY(ptraced_long == -1L && errno != 0)) {
            /* it's possible i'm trying to read partially oob */
            if (errno == EIO || errno == EFAULT) {
                int j;
                /* read backwards until we get a good read, then shift out the right value */
                for (j = 1, errno = 0; j < sizeof(long); j++, errno = 0) {
                    /* try for a shifted ptrace - 'continue' (i.e. try an increased shift) if it fails */
                    ptraced_long = ptrace(PTRACE_PEEKDATA, attach_state->pid, ptrace_address - j, NULL);
                    if ((ptraced_long == -1L) && (errno == EIO || errno == EFAULT))
                        continue;

                    /* store it with the appropriate offset */
                    uint8_t* new_memory_ptr = (uint8_t*)(&ptraced_long) + j;
                    memcpy(dest_buffer + nread, new_memory_ptr, sizeof(long) - j);
                    nread += sizeof(long) - j;

                    /* interrupt the partial gathering process */
                    break;
                }
            }
            /* interrupt the gathering process */
            break;
        }
        /* otherwise, ptrace() worked - store the data */
        memcpy(dest_buffer + nread, &ptraced_long, sizeof(long));
    }
#endif
    return nread;
}

/*
 * sm_peekdata - fills the peekbuf cache with memory from the process
 * 
 * This routine calls either `ptrace(PEEKDATA, ...)` or `pread(...)`,
 * and fills the peekbuf cache, to make a local mirror of the process memory we're interested in.
 * `sm_attach()` MUST be called before this function.
 */

inline bool sm_peekdata(struct peekbuf_t* peekbuf, const void *addr, uint16_t length, const mem64_t **result_ptr, size_t *memlength, struct attach_state_t* attach_state)
{
    const char *reqaddr = addr;
    unsigned int i;
    unsigned int missing_bytes;

    assert(peekbuf->size <= MAX_PEEKBUF_SIZE);
    assert(result_ptr != NULL);
    assert(memlength != NULL);

    /* check if we have a full cache hit */
    if (peekbuf->base != NULL &&
        reqaddr >= peekbuf->base &&
        (unsigned long) (reqaddr + length - peekbuf->base) <= peekbuf->size)
    {
        *result_ptr = (mem64_t*)&peekbuf->cache[reqaddr - peekbuf->base];
        *memlength = peekbuf->base - reqaddr + peekbuf->size;
        return true;
    }
    else if (peekbuf->base != NULL &&
             reqaddr >= peekbuf->base &&
             (unsigned long) (reqaddr - peekbuf->base) < peekbuf->size)
    {
        assert(peekbuf->size != 0);

        /* partial hit, we have some of the data but not all, so remove old entries - shift the frame by as far as is necessary */
        missing_bytes = (reqaddr + length) - (peekbuf->base + peekbuf->size);
        /* round up to the nearest PEEKDATA_CHUNK multiple, that is what could
         * potentially be read and we have to fit it all */
        missing_bytes = PEEKDATA_CHUNK * (1 + (missing_bytes-1) / PEEKDATA_CHUNK);

        /* head shift if necessary */
        if (peekbuf->size + missing_bytes > MAX_PEEKBUF_SIZE)
        {
            unsigned int shift_size = reqaddr - peekbuf->base;
            shift_size = PEEKDATA_CHUNK * (shift_size / PEEKDATA_CHUNK);

            memmove(peekbuf->cache, &peekbuf->cache[shift_size], peekbuf->size-shift_size);

            peekbuf->size -= shift_size;
            peekbuf->base += shift_size;
        }
    }
    else {
        /* cache miss, invalidate the cache */
        missing_bytes = length;
        peekbuf->size = 0;
        peekbuf->base = reqaddr;
    }

    /* we need to retrieve memory to complete the request */
    for (i = 0; i < missing_bytes; i += PEEKDATA_CHUNK)
    {
        const char *target_address = peekbuf->base + peekbuf->size;
        size_t len = sm_readmemory(&peekbuf->cache[peekbuf->size], target_address, PEEKDATA_CHUNK, attach_state);

        /* check if the read succeeded */
        if (UNLIKELY(len < PEEKDATA_CHUNK)) {
            if (len == 0) {
                /* hard failure to retrieve memory */
                *result_ptr = NULL;
                *memlength = 0;
                return false;
            }
            /* go ahead with the partial read and stop the gathering process */
            peekbuf->size += len;
            break;
        }
        
        /* otherwise, the read worked */
        peekbuf->size += PEEKDATA_CHUNK;
    }

    /* return result to caller */
    *result_ptr = (mem64_t*)&peekbuf->cache[reqaddr - peekbuf->base];
    *memlength = peekbuf->base - reqaddr + peekbuf->size;
    return true;
}

static inline void print_a_dot(void)
{
    fprintf(stderr, ".");
    fflush(stderr);
}

static inline uint16_t flags_to_memlength(scan_data_type_t scan_data_type, match_flags flags)
{
    switch(scan_data_type)
    {
        case BYTEARRAY:
        case STRING:
            return flags;
            break;
        default: /* numbers */
                 if (flags & flags_64b) return 8;
            else if (flags & flags_32b) return 4;
            else if (flags & flags_16b) return 2;
            else if (flags & flags_8b ) return 1;
            else    /* it can't be a variable of any size */ return 0;
            break;
    }
}

static int get_number_of_threads(int num_parallel_jobs) {
    if (num_parallel_jobs == 0) 
    {
        /* query os for number of cores */
        return get_nprocs();
    }
    else 
    {
        return num_parallel_jobs;
    }
}

#define ORDERED_MATCHES 1

struct sm_checkmatches_thread_shared {
    struct attach_state_t *attach_state;
    const uservalue_t *uservalue;
    scan_data_type_t scan_data_type;
    int num_threads;
    size_t bytes_per_sample;
    globals_t *vars;
};

struct sm_checkmatches_thread_args {
    pthread_t thread;
    int thread_id;
    struct sm_checkmatches_thread_shared* shared;

    /* input */
    matches_and_old_values_array *input_matches;

    /* output */
    unsigned long num_matches;
    matches_and_old_values_array *output_matches;

    /* error */
    char const * error_str; /* NULL if no error */
};

static void* sm_checkmatches_thread_func(void* args) {
    struct sm_checkmatches_thread_args* thread_args = (struct sm_checkmatches_thread_args*)args;
    
    matches_and_old_values_swath *reading_swath_index = thread_args->input_matches->swaths;

    /* create matches data structure for this thread */
    if (!(thread_args->output_matches = allocate_array(thread_args->output_matches, thread_args->input_matches->max_needed_bytes)))
    {
        thread_args->error_str = "could not allocate match array";
        return NULL;
    }

    matches_and_old_values_swath *writing_swath_index = thread_args->output_matches->swaths;
    writing_swath_index->first_byte_in_child = NULL;
    writing_swath_index->number_of_bytes = 0;

    struct peekbuf_t peekbuf;
    memset(&peekbuf, 0, sizeof(peekbuf));

    size_t swath_index = 0;
    size_t bytes_scanned_until_dot = 0;
    bool stop_flag = false;

    while (reading_swath_index->number_of_bytes > 0) {
        if (swath_index % thread_args->shared->num_threads == thread_args->thread_id) {

            int required_extra_bytes_to_record = 0;
            size_t reading_iterator = 0;
            
            while (reading_iterator < reading_swath_index->number_of_bytes) {
                match_flags old_flags = reading_swath_index->data[reading_iterator].match_info;
                unsigned int old_length = flags_to_memlength(thread_args->shared->scan_data_type, old_flags);
                void *address = reading_swath_index->first_byte_in_child + reading_iterator;
                
                /* read value from this address */
                unsigned int match_length = 0;
                const mem64_t *memory_ptr;
                size_t memlength;
                match_flags checkflags;
                if (UNLIKELY(sm_peekdata(&peekbuf, address, old_length, &memory_ptr, &memlength, thread_args->shared->attach_state) == false))
                {
                    /* If we can't look at the data here, just abort the whole recording, something bad happened */
                    required_extra_bytes_to_record = 0;
                }
                else if (old_flags != flags_empty) /* Test only valid old matches */
                {
                    value_t old_val = data_to_val_aux(reading_swath_index, reading_iterator, reading_swath_index->number_of_bytes);
                    memlength = old_length < memlength ? old_length : memlength;

                    checkflags = flags_empty;

                    match_length = (*sm_scan_routine)(memory_ptr, memlength, &old_val, thread_args->shared->uservalue, &checkflags);
                }

                if (match_length > 0)
                {
                    assert(match_length <= memlength);

                    /* Still a candidate. Write data.
                    - We can get away with overwriting in the same array because it is guaranteed to take up the same number of bytes or fewer,
                        and because we copied out the reading swath metadata already.
                    - We can get away with assuming that the pointers will stay valid,
                        because as we never add more data to the array than there was before, it will not reallocate. */

                    writing_swath_index = add_element(&thread_args->output_matches, writing_swath_index, address,
                                                    get_u8b(memory_ptr), checkflags);

                    ++thread_args->num_matches;

                    required_extra_bytes_to_record = match_length - 1;
                }
                else if (required_extra_bytes_to_record)
                {
                    writing_swath_index = add_element(&thread_args->output_matches, writing_swath_index, address,
                                                    get_u8b(memory_ptr), flags_empty);
                    --required_extra_bytes_to_record;
                }
                reading_iterator++;
            }
        }

        /* calculate progress */
        if (thread_args->thread_id == 0) 
        {
            bytes_scanned_until_dot += reading_swath_index->number_of_bytes;
            if (bytes_scanned_until_dot >= thread_args->shared->bytes_per_sample * SAMPLES_PER_DOT) 
            {
                /* for user, just print a dot */
                print_a_dot();

                /* for front-end, update percentage */
                thread_args->shared->vars->scan_progress += PROGRESS_PER_SAMPLE * SAMPLES_PER_DOT;
                
                bytes_scanned_until_dot = 0;
            }
        }

        reading_swath_index = local_address_beyond_last_element(reading_swath_index);
        swath_index++;

        /* check if we are interrupted */
        stop_flag = atomic_load(&thread_args->shared->vars->stop_flag);
        if (stop_flag) {
            break;
        }
    }

    if (!(thread_args->output_matches = null_terminate(thread_args->output_matches, writing_swath_index)))
    {
        thread_args->error_str = "memory allocation error while reducing matches-array size";
        return NULL;
    }

    return NULL;
}

/* This is the function that handles when you enter a value (or >, <, =) for the second or later time (i.e. when there's already a list of matches);
 * it reduces the list to those that still match. It returns false on failure to attach, detach, or reallocate memory, otherwise true. */
bool sm_checkmatches(globals_t *vars,
                     scan_match_type_t match_type,
                     const uservalue_t *uservalue)
{
    struct attach_state_t attach_state;

    if (sm_choose_scanroutine(vars->options.scan_data_type, match_type, uservalue, vars->options.reverse_endianness) == false)
    {
        show_error("unsupported scan for current data type.\n");
        return false;
    }

    assert(sm_scan_routine);

    /* stop and attach to the target */
    if (sm_attach(vars->target, &attach_state) == false)
    {
        return false;
    }

    INTERRUPTABLESCAN();

    /* reset number of matches before summing results from each thread */
    vars->num_matches = 0;
    vars->scan_progress = 0.0;

    matches_and_old_values_swath *tmp_swath_index = vars->matches->swaths;
    size_t number_of_swaths = 0;
    size_t total_scan_bytes = 0;

    while(tmp_swath_index->number_of_bytes)
    {
        number_of_swaths++;
        total_scan_bytes += tmp_swath_index->number_of_bytes;
        tmp_swath_index = (matches_and_old_values_swath *)(&tmp_swath_index->data[tmp_swath_index->number_of_bytes]);
    }

    /* get number of threads to use */
    int num_threads = get_number_of_threads(vars->options.num_parallel_jobs);

    /* if number_of_swaths is less than threads, reduce number of threads */
    if (number_of_swaths < num_threads) 
    {
        num_threads = number_of_swaths;
    }

    /* create threads */
    struct sm_checkmatches_thread_args* thread_args;

    thread_args = malloc(num_threads * sizeof(struct sm_checkmatches_thread_args));
    if (thread_args == NULL) 
    {
        show_error("could not allocate kernel_args array\n");
        return false;
    }
    memset(thread_args, 0, num_threads * sizeof(struct sm_checkmatches_thread_args));

    struct sm_checkmatches_thread_shared shared;
    memset(&shared, 0, sizeof(shared));
    shared.num_threads = num_threads;
    shared.attach_state = &attach_state;
    shared.uservalue = uservalue;
    shared.scan_data_type = vars->options.scan_data_type;
    shared.bytes_per_sample = total_scan_bytes / NUM_SAMPLES;
    shared.vars = vars;

    for (int thread_id = 0; thread_id < num_threads; thread_id++) 
    {
        thread_args[thread_id].thread_id = thread_id;
        thread_args[thread_id].shared = &shared;

        thread_args[thread_id].input_matches = vars->matches;
        thread_args[thread_id].num_matches = 0;
        thread_args[thread_id].output_matches = NULL;
        thread_args[thread_id].error_str = NULL;
    
        int ret = pthread_create(&thread_args[thread_id].thread, NULL, sm_checkmatches_thread_func, (void*)&thread_args[thread_id]);
        if (ret) {
            show_error("could not create thread %d\n", thread_id);
            return false;
        }
    }


    /* allocate new master swath array to store results, 
       of same size as current master swath array 
    */
    matches_and_old_values_array *new_matches = NULL;
    if (!(new_matches = allocate_array(new_matches, vars->matches->max_needed_bytes)))
    {
        show_error("could not allocate match array\n");
        return false;
    }
    matches_and_old_values_swath *writing_swath_index;
    writing_swath_index = new_matches->swaths;
    writing_swath_index->first_byte_in_child = NULL;
    writing_swath_index->number_of_bytes = 0;

    /* join threads, sum up matches and merge matches */
    bool error = false;
    for (int i = 0; i < num_threads; i++) 
    {
        int ret = pthread_join(thread_args[i].thread, NULL);
        if (ret) 
        {
            show_error("could not join thread %d\n", i);
            return false;
        }

        /* check if thread failed */
        if (thread_args[i].error_str != NULL) 
        {
            show_error("thread %d hit error: %s\n", i, thread_args[i].error_str);
            error = true;
            continue;
        }
        
        /* sum up matches */
        vars->num_matches += thread_args[i].num_matches;

        /* merge matches */
        writing_swath_index = concat_array(&new_matches, writing_swath_index, thread_args[i].output_matches);
        free(thread_args[i].output_matches);
    }

    free(thread_args);

    free(vars->matches);
    vars->matches = new_matches;
    
    /* store if we were interrupted */
    bool interrupted_scan = atomic_load(&vars->stop_flag); 

    ENDINTERRUPTABLE();

    /* if any thread failed */
    if (error) 
    {
        return false;
    }

    /* null terminate matches */
    if (!(vars->matches = null_terminate(vars->matches, writing_swath_index)))
    {
        show_error("memory allocation error while reducing matches-array size\n");
        return false;
    }

    if (interrupted_scan) 
    {
        show_info("interrupted scan\n");
    }

    show_user("ok\n");

    /* tell front-end we've done */
    vars->scan_progress = MAX_PROGRESS;

    show_info("we currently have %ld matches.\n", vars->num_matches);

    /* okay, detach */
    return sm_detach(vars->target, &attach_state);
}

struct sm_searchregions_thread_shared {
    int num_threads;
    size_t search_stride;           /* how many bytes to search at a time (for each thread) */
    size_t max_read_size;           /* how many bytes to read at a time (for each thread), should be search_stride + max_vlt_size */
    size_t total_matches_size;      /* total size of matches array */
    struct attach_state_t *attach_state;
    const uservalue_t *uservalue;
    size_t total_scan_bytes;        /* total number of bytes to scan */
#if ORDERED_MATCHES
    size_t total_scan_blocks;       /* total number of blocks to scan, calculated as `size of each regian in bytes / search stride` rounded up to multiple of search stride, then summed together */
#endif
    globals_t *vars;
};

struct sm_searchregions_thread_args {
    pthread_t thread;
    int thread_id;
    struct sm_searchregions_thread_shared* shared;
    
    /* input (head of regions to search) */
    element_t const *head;

    /* output */
    unsigned long num_matches;
    matches_and_old_values_array *matches;
    matches_and_old_values_swath *writing_swath_index;

    /* error */
    char const * error_str; /* NULL if no error */
};

static void* sm_searchregions_thread_func(void* args) {
    struct sm_searchregions_thread_args* thread_args = (struct sm_searchregions_thread_args*)args;

    /* create matches data structure for this thread */
    if (!(thread_args->matches = allocate_array(thread_args->matches, thread_args->shared->total_matches_size)))
    {
        thread_args->error_str = "could not allocate match array\n";
        return NULL;
    }
    
    thread_args->writing_swath_index = thread_args->matches->swaths; 
    thread_args->writing_swath_index->first_byte_in_child = NULL;
    thread_args->writing_swath_index->number_of_bytes = 0;

    element_t const *n = thread_args->head;
    size_t regnum = 0;
    bool stop_flag = false;

#if ORDERED_MATCHES
    size_t blocks_to_scan = thread_args->shared->total_scan_blocks / thread_args->shared->num_threads;
    const size_t block_start = blocks_to_scan * thread_args->thread_id;
    /* if this is the last thread, make sure all blocks at the end are covered */
    if (thread_args->thread_id == thread_args->shared->num_threads - 1) {
        blocks_to_scan = thread_args->shared->total_scan_blocks - block_start;
    }
    size_t block_current = 0;
#endif

    while (n) 
    {
        region_t const *r = (region_t const *)n->data;
        unsigned char *data = NULL;

        size_t bytes_per_sample = r->size / NUM_SAMPLES;
        size_t bytes_scanned_until_dot = 0;
        
        /* allocate data array */
        size_t alloc_size = MIN(r->size, thread_args->shared->max_read_size);
        if ((data = malloc(alloc_size * sizeof(char))) == NULL) 
        {
            thread_args->error_str = "sorry, there was a memory allocation error.\n";
            return NULL;
        }

        /* print a progress meter so user knows we haven't crashed */
        if (thread_args->thread_id == 0)
        {
            show_user("%02lu/%02lu searching %#10lx - %#10lx", ++regnum,
                    thread_args->shared->vars->regions->size, (unsigned long)r->start, (unsigned long)r->start + r->size);
            fflush(stderr);
        }

        /* For every offset, check if we have a match. */
#if ORDERED_MATCHES
        size_t offset = 0;
        while (block_current < block_start + blocks_to_scan && offset < r->size) {
            /* check if current block is relevant for this thread, if not go to next */
            if (block_current < block_start) {
                ++block_current;
                offset += thread_args->shared->search_stride;
                continue;
            }
#else
        for (size_t offset = (size_t)thread_args->thread_id * thread_args->shared->search_stride; offset < r->size; offset += thread_args->shared->search_stride * (size_t)thread_args->shared->num_threads) 
        {
#endif

            void *reg_pos = r->start + offset;

            /* load the next buffer block */
            size_t read_size = MIN(r->size - offset, thread_args->shared->max_read_size);
            size_t nread = sm_readmemory(data, reg_pos, read_size, thread_args->shared->attach_state);
            /* check if the read succeeded */
            if ((nread == 0) && (offset == 0)) 
            {
                /* Failed on first read, which means region not exist. */
                show_warn("reading region %02u failed.\n", r->start);
                break;
            }

            int required_extra_bytes_to_record = 0;

            /* search for matches */
            size_t search_area = MIN(nread, thread_args->shared->search_stride);
            for (size_t i = 0; i < search_area; i++) 
            {
                const mem64_t* memory_ptr = (mem64_t*)(data + i);
                unsigned int match_length;
                match_flags checkflags;

                /* initialize checkflags */
                checkflags = flags_empty;
                
                /* check if we have a match */
                match_length = (*sm_scan_routine)(memory_ptr, search_area - i, NULL, thread_args->shared->uservalue, &checkflags);
                
                if (UNLIKELY(match_length > 0))
                {
                    assert(match_length <= nread);
                    thread_args->writing_swath_index = add_element(&thread_args->matches, thread_args->writing_swath_index, reg_pos + i,
                                                    get_u8b(memory_ptr), checkflags);
                    
                    thread_args->num_matches++;
                    
                    required_extra_bytes_to_record = match_length - 1;
                }
                else if (required_extra_bytes_to_record)
                {
                    thread_args->writing_swath_index = add_element(&thread_args->matches, thread_args->writing_swath_index, reg_pos + i,
                                                    get_u8b(memory_ptr), flags_empty);
                    --required_extra_bytes_to_record;
                }
                
            }

            /* calculate progress */
            if (thread_args->thread_id == 0) 
            {
                bytes_scanned_until_dot += thread_args->shared->search_stride * (size_t)thread_args->shared->num_threads; /* approximation */
                if (bytes_scanned_until_dot >= bytes_per_sample * SAMPLES_PER_DOT) 
                {
                    /* for user, just print a dot */
                    print_a_dot();
                    
                    /* for front-end, update percentage */
                    size_t bytes_per_dot = r->size / NUM_DOTS;
                    double progress_per_dot = (double)bytes_per_dot / thread_args->shared->total_scan_bytes;
                    thread_args->shared->vars->scan_progress += progress_per_dot;

                    bytes_scanned_until_dot = 0;
                }
            }

            /* check if we are interrupted */
            stop_flag = atomic_load(&thread_args->shared->vars->stop_flag);
            if (stop_flag) 
            {
                break;
            }

#if ORDERED_MATCHES
            /* go to next block */
            ++block_current;
            offset += thread_args->shared->search_stride;
#endif
        }
        
        free(data);

        n = n->next;

        /* check if we are interrupted */
        if (stop_flag) 
        {
            break;
        }

        if (thread_args->thread_id == 0) 
        {
            show_user("ok\n");
        }  
    }

    if (!(thread_args->matches = null_terminate(thread_args->matches, thread_args->writing_swath_index)))
    {
        thread_args->error_str = "memory allocation error while reducing matches-array size\n";
        return NULL;
    }

    return NULL;
}

/* sm_searchregions() performs an initial search of the process for values matching `uservalue` */
bool sm_searchregions(globals_t *vars, scan_match_type_t match_type, const uservalue_t *uservalue)
{
    struct attach_state_t attach_state;

    size_t total_matches_size = 0;
    size_t total_scan_bytes = 0;
#if ORDERED_MATCHES
    size_t total_scan_blocks = 0;
#endif
    element_t const *n = vars->regions->head;    

    /* select scanroutine */
    if (sm_choose_scanroutine(vars->options.scan_data_type, match_type, uservalue, vars->options.reverse_endianness) == false)
    {
        show_error("unsupported scan for current data type.\n"); 
        return false;
    }

    assert(sm_scan_routine);

    /* stop and attach to the target */
    if (sm_attach(vars->target, &attach_state) == false) 
    {
        return false;
    }
   
    /* make sure we have some regions to search */
    if (vars->regions->size == 0) 
    {
        show_warn("no regions defined, perhaps you deleted them all?\n");
        show_info("use the \"reset\" command to refresh regions.\n");
        return sm_detach(vars->target, &attach_state);
    }

    INTERRUPTABLESCAN();

    total_matches_size = sizeof(matches_and_old_values_array);

    while (n) 
    {
        total_matches_size += ((region_t *)(n->data))->size * sizeof(old_value_and_match_info) + sizeof(matches_and_old_values_swath);
        n = n->next;
    }
    
    total_matches_size += sizeof(matches_and_old_values_swath); /* for null terminate */
    
    show_debug("allocate array, max size %ld\n", total_matches_size);

    /* The maximum logical size is a comfortable 1MiB (increasing it does not help).
     * The actual allocation is that plus the rounded size of the maximum possible VLT.
     * This is needed because the last byte might be scanned as max size VLT,
     * thus need (2^16 - 2) extra bytes after it */
#define MAX_BUFFER_SIZE (1<<20)
#define MAX_ALLOC_SIZE  (MAX_BUFFER_SIZE + (1<<16))
    
    /* divide up work for each thread,
       each thread will read a chunk of memory of size max_read_size (or less if near end of region),
       however match searches will only start from offsets 0 to search_stride */
    size_t search_stride = MAX_BUFFER_SIZE;
    size_t max_read_size = MAX_ALLOC_SIZE;

    /* get total number of bytes */
    for (n = vars->regions->head; n; n = n->next) {
        total_scan_bytes += ((region_t *)n->data)->size;
#if ORDERED_MATCHES
        const size_t round_up = search_stride - ((region_t *)n->data)->size % search_stride;
        total_scan_blocks += (((region_t *)n->data)->size + round_up) / search_stride;
#endif
    }

    /* get number of threads to use */
    int num_threads = get_number_of_threads(vars->options.num_parallel_jobs);

    /* if total bytes to read is less than num_threads * search_stride, reduce number of threads */
    if (total_scan_bytes < num_threads * search_stride) 
    {
        num_threads = total_scan_bytes / search_stride;
    }

    vars->scan_progress = 0.0;
    vars->stop_flag = false;
    n = vars->regions->head;

    /* create threads */
    struct sm_searchregions_thread_args* thread_args;

    thread_args = malloc(num_threads * sizeof(struct sm_searchregions_thread_args));
    if (thread_args == NULL) 
    {
        show_error("could not allocate kernel_args array\n");
        return false;
    }
    memset(thread_args, 0, num_threads * sizeof(struct sm_searchregions_thread_args));

    struct sm_searchregions_thread_shared shared;
    memset(&shared, 0, sizeof(shared));
    shared.num_threads = num_threads;
    shared.search_stride = search_stride;
    shared.max_read_size = max_read_size;
    shared.total_matches_size = total_matches_size;
    shared.attach_state = &attach_state;
    shared.uservalue = uservalue;
    shared.total_scan_bytes = total_scan_bytes;
#if ORDERED_MATCHES
    shared.total_scan_blocks = total_scan_blocks;
#endif
    shared.vars = vars;

    for (int thread_id = 0; thread_id < num_threads; thread_id++) 
    {
        thread_args[thread_id].thread_id = thread_id;
        thread_args[thread_id].shared = &shared;

        thread_args[thread_id].head = n;
        thread_args[thread_id].num_matches = 0;
        thread_args[thread_id].matches = NULL;
        thread_args[thread_id].writing_swath_index = NULL;
        thread_args[thread_id].error_str = NULL;
    
        int ret = pthread_create(&thread_args[thread_id].thread, NULL, sm_searchregions_thread_func, (void*)&thread_args[thread_id]);
        if (ret) 
        {
            show_error("could not create thread %d\n", thread_id);
            return false;
        }
    }
    
    /* allocate master swath array */
    if (!(vars->matches = allocate_array(vars->matches, total_matches_size * num_threads)))
    {
        show_error("could not allocate match array\n");
        return false;
    }
    matches_and_old_values_swath *writing_swath_index;
    writing_swath_index = vars->matches->swaths;
    writing_swath_index->first_byte_in_child = NULL;
    writing_swath_index->number_of_bytes = 0;

    /* reset number of matches before summing results from each thread */
    vars->num_matches = 0;

    /* join threads, sum up matches and merge matches */
    bool error = false;
    for (int i = 0; i < num_threads; i++) 
    {
        int ret = pthread_join(thread_args[i].thread, NULL);
        if (ret) {
            show_error("could not join thread %d\n", i);
            return false;
        }

        /* check if thread hit error */
        if (thread_args[i].error_str != NULL) 
        {
            show_error("thread %d hit error: %s\n", i, thread_args[i].error_str);
            error = true;
            continue;
        }
        
        /* sum up matches */
        vars->num_matches += thread_args[i].num_matches;

        /* merge matches */
        writing_swath_index = concat_array(&vars->matches, writing_swath_index, thread_args[i].matches);
        free(thread_args[i].matches);
    }

    free(thread_args);

    /* store if we were interrupted */
    bool interrupted_scan = atomic_load(&vars->stop_flag);

    ENDINTERRUPTABLE();

    if (error) 
    {
        return false;
    }

    /* null terminate matches */
    if (!(vars->matches = null_terminate(vars->matches, writing_swath_index)))
    {
        show_error("memory allocation error while reducing matches-array size\n");
        return false;
    }

    if (interrupted_scan) 
    {
        show_info("interrupted scan\n");
    }

    /* tell front-end we've finished */
    vars->scan_progress = MAX_PROGRESS;

    show_info("we currently have %ld matches.\n", vars->num_matches);

    /* okay, detach */
    return sm_detach(vars->target, &attach_state);
}

/* Needs to support only ANYNUMBER types */
bool sm_setaddr(pid_t target, void *addr, const value_t *to)
{
    struct attach_state_t attach_state;

    unsigned int i;
    uint8_t memarray[sizeof(uint64_t)] = {0};
    size_t memlength;

    /* stop and attach to the target */
    if (sm_attach(target, &attach_state) == false)
    {
        return false;
    }

    memlength = sm_readmemory(memarray, addr, sizeof(uint64_t), &attach_state);
    if (memlength == 0) {
        show_error("couldn't access the target address %10p\n", addr);
        return false;
    }

    unsigned int val_length = flags_to_memlength(ANYNUMBER, to->flags);
    if (val_length > 0) {
        /* Basically, overwrite as much of the data as makes sense, and no more. */
        memcpy(memarray, to->bytes, val_length);
    }
    else {
        show_error("could not determine type to poke.\n");
        return false;
    }

    if (sm_globals.options.no_ptrace)
    {
#if HAVE_PROCMEM
        if (pwrite(attach_state.procmem_fd, memarray, sizeof(uint64_t), (long)addr) == -1)
        {
            return false;
        }
#else
        return false;
#endif
    }
    else
    {
        /* Assume `sizeof(uint64_t)` is a multiple of `sizeof(long)` */
        for (i = 0; i < sizeof(uint64_t); i += sizeof(long))
        {
            if (ptrace(PTRACE_POKEDATA, target, addr + i, *(long*)(memarray + i)) == -1L) {
                return false;
            }
        }
    }

    return sm_detach(target, &attach_state);
}

bool sm_read_array(pid_t target, const void *addr, void *buf, size_t len)
{
    struct attach_state_t attach_state;

    /* stop and attach to the target */
    if (sm_attach(target, &attach_state) == false)
    {
        return false;
    }

    size_t nread = sm_readmemory(buf, addr, len, &attach_state);
    if (nread < len)
    {
        sm_detach(target, &attach_state);
        return false;
    }

    return sm_detach(target, &attach_state);
}

/* TODO: may use /proc/<pid>/mem here */
bool sm_write_array(pid_t target, void *addr, const void *data, size_t len)
{
    struct attach_state_t attach_state;

    unsigned int i,j;
    long peek_value;

    /* stop and attach to the target */
    if (sm_attach(target, &attach_state) == false)
    {
        return false;
    }

    if (sm_globals.options.no_ptrace)
    {
#if HAVE_PROCMEM
        if (pwrite(attach_state.procmem_fd, data, len, (long)addr) == -1)
        {
            return false;
        }
#else
        return false;
#endif
    }
    else
    {
        for (i = 0; i + sizeof(long) < len; i += sizeof(long))
        {
            if (ptrace(PTRACE_POKEDATA, target, addr + i, *(long *)(data + i)) == -1L) {
                return false;
            }
        }

        if (len - i > 0) /* something left (shorter than a long) */
        {
            if (len > sizeof(long)) /* rewrite last sizeof(long) bytes of the buffer */
            {
                if (ptrace(PTRACE_POKEDATA, target, addr + len - sizeof(long), *(long *)(data + len - sizeof(long))) == -1L) {
                    return false;
                }
            }
            else /* we have to play with bits... */
            {
                /* try all possible shifting read and write */
                for(j = 0; j <= sizeof(long) - (len - i); ++j)
                {
                    errno = 0;
                    if(((peek_value = ptrace(PTRACE_PEEKDATA, target, addr - j, NULL)) == -1L) && (errno != 0))
                    {
                        if (errno == EIO || errno == EFAULT) /* may try next shift */
                            continue;
                        else
                        {
                            show_error("%s failed.\n", __func__);
                            return false;
                        }
                    }
                    else /* peek success */
                    {
                        /* write back */
                        memcpy(((int8_t*)&peek_value)+j, data+i, len-i);

                        if (ptrace(PTRACE_POKEDATA, target, addr - j, peek_value) == -1L)
                        {
                            show_error("%s failed.\n", __func__);
                            return false;
                        }

                        break;
                    }
                }
            }
        }
    }

    return sm_detach(target, &attach_state);
}
