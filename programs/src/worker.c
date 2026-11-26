/*
 * worker.c - multithreaded test program (CONCURRENCY element of the project).
 *
 * Usage: worker N
 *   N = 0 : the main thread does all the work (no threads are created)
 *   N > 0 : N POSIX threads split the work and combine results under a mutex
 *
 * Why this exists: thread creation and synchronisation need syscalls that a
 * single-threaded run never makes (clone3, futex, extra mmap/mprotect for
 * thread stacks, rseq/set_robust_list per thread). Training on "worker 0" and
 * testing on "worker 4" shows whether a policy generalises to concurrent use.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define WORK 4000000L

static long total = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long nthreads = 1;

static long compute(long start, long step) {
    long s = 0;
    for (long i = start; i < WORK; i += step) s += i % 7;
    return s;
}

static void *thread_main(void *arg) {
    long id = (long)arg;
    long s = compute(id, nthreads);
    pthread_mutex_lock(&lock);          /* contended lock -> futex syscalls */
    total += s;
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 0;
    if (n <= 0) {
        total = compute(0, 1);
    } else {
        nthreads = n;
        pthread_t *t = malloc(sizeof(pthread_t) * n);
        for (long i = 0; i < n; i++) pthread_create(&t[i], NULL, thread_main, (void *)i);
        for (long i = 0; i < n; i++) pthread_join(t[i], NULL);
        free(t);
    }
    printf("total=%ld\n", total);
    return 0;
}
