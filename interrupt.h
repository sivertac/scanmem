/*
    Interrupt handling.

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

#ifndef INTERRUPT_H
#define INTERRUPT_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE    /* for sighandler_t */
#endif

#include <setjmp.h>
#include <signal.h>

extern sigjmp_buf jmpbuf;       /* used when aborting a command due to an interrupt */
extern struct sigaction oldsig;        /* reinstalled before longjmp */
extern unsigned intr_used;

/* signal handler used to handle an interrupt during commands */
void interrupted(int);

/* signal handler used to handle an interrupt during scans */
void interrupt_scan(int);

void set_interrupted_signal();

#define INTERRUPTABLE() (set_interrupted_signal(), sigsetjmp(jmpbuf, 1))


#define INTERRUPTABLESCAN()                                         \
do {                                                                \
    struct sigaction interrupt_action = {};                         \
    interrupt_action.sa_handler = interrupt_scan;                   \
    if (sigaction(SIGINT, &interrupt_action, &oldsig) == -1) {      \
        exit(EXIT_FAILURE);                                         \
    }                                                               \
    intr_used = 1;                                                  \
} while (0)
    
    
#define ENDINTERRUPTABLE()                                          \
do {                                                                \
    if (intr_used) {                                                \
        if (sigaction(SIGINT, &oldsig, NULL) == -1) {               \
            exit(EXIT_FAILURE);                                     \
        }                                                           \
    }                                                               \
    intr_used = 0;                                                  \
} while (0)


#endif /* INTERRUPT_H */
