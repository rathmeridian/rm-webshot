/*
 * threadpool.h - A small fixed-size worker pool.
 *
 * Scanning is almost entirely spent waiting on the network, so running many
 * connection attempts at once is what makes the tool fast. A pool with a fixed
 * number of workers gives us that concurrency while keeping a hard ceiling on
 * open file descriptors and memory.
 *
 * Usage:
 *     threadpool_t *tp = threadpool_create(64);
 *     for (...) threadpool_submit(tp, my_job_fn, &jobs[i]);
 *     threadpool_wait(tp);      // block until every job has finished
 *     threadpool_destroy(tp);
 *
 * Job functions run concurrently, so anything they touch must either be
 * private to that job or protected by the caller.
 */

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <stddef.h>

/* Signature of a unit of work. The pool never looks inside `arg`. */
typedef void (*tp_job_fn)(void *arg);

/* Opaque pool handle; the layout lives in threadpool.c. */
typedef struct threadpool threadpool_t;

/*
 * Create a pool with `nthreads` workers. Returns NULL on failure.
 * A count of 0 is treated as 1.
 */
threadpool_t *threadpool_create(size_t nthreads);

/*
 * Queue a job. Returns 0 on success, -1 if the job could not be queued.
 * `arg` must stay valid until the job has run.
 */
int threadpool_submit(threadpool_t *tp, tp_job_fn fn, void *arg);

/* Block until the queue is empty and no worker is still running a job. */
void threadpool_wait(threadpool_t *tp);

/* Stop the workers and release the pool. Safe to call after threadpool_wait. */
void threadpool_destroy(threadpool_t *tp);

#endif /* THREADPOOL_H */
