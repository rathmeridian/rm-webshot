/*
 * threadpool.c - Implementation of the worker pool declared in threadpool.h.
 *
 * The design is deliberately plain: one mutex protects a singly linked job
 * queue, one condition variable wakes idle workers, and a second condition
 * variable wakes anyone waiting for the pool to go idle.
 */

#include "threadpool.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

/* One queued job. Freed by the worker that runs it. */
typedef struct tp_task {
    tp_job_fn fn;
    void *arg;
    struct tp_task *next;
} tp_task_t;

struct threadpool {
    pthread_t *threads;
    size_t nthreads;

    pthread_mutex_t lock;   /* guards every field below */
    pthread_cond_t work_ready; /* signalled when a job is queued or on shutdown */
    pthread_cond_t all_idle;   /* signalled when pending reaches zero */

    tp_task_t *head; /* oldest queued job */
    tp_task_t *tail; /* newest queued job */

    size_t pending;  /* queued jobs plus jobs currently executing */
    int shutting_down;
};

/*
 * Worker loop: take a job, run it, repeat. Exits when the pool is told to shut
 * down and the queue has drained.
 */
static void *worker_main(void *arg)
{
    threadpool_t *tp = (threadpool_t *)arg;

    for (;;) {
        pthread_mutex_lock(&tp->lock);

        /* Sleep until there is work or the pool is closing. */
        while (tp->head == NULL && !tp->shutting_down) {
            pthread_cond_wait(&tp->work_ready, &tp->lock);
        }

        if (tp->head == NULL && tp->shutting_down) {
            pthread_mutex_unlock(&tp->lock);
            break;
        }

        /* Pop the oldest job. */
        tp_task_t *task = tp->head;
        tp->head = task->next;
        if (tp->head == NULL) {
            tp->tail = NULL;
        }

        pthread_mutex_unlock(&tp->lock);

        /* Run outside the lock so other workers can proceed in parallel. */
        task->fn(task->arg);
        free(task);

        /*
         * Only now is the job truly finished, so decrement here rather than
         * when it was dequeued. Otherwise threadpool_wait could return while
         * a job was still running.
         */
        pthread_mutex_lock(&tp->lock);
        tp->pending--;
        if (tp->pending == 0) {
            pthread_cond_broadcast(&tp->all_idle);
        }
        pthread_mutex_unlock(&tp->lock);
    }

    return NULL;
}

threadpool_t *threadpool_create(size_t nthreads)
{
    if (nthreads == 0) {
        nthreads = 1;
    }

    threadpool_t *tp = calloc(1, sizeof(*tp));
    if (tp == NULL) {
        return NULL;
    }

    tp->threads = calloc(nthreads, sizeof(*tp->threads));
    if (tp->threads == NULL) {
        free(tp);
        return NULL;
    }

    pthread_mutex_init(&tp->lock, NULL);
    pthread_cond_init(&tp->work_ready, NULL);
    pthread_cond_init(&tp->all_idle, NULL);

    /*
     * Start the workers. If some fail to start we keep the ones that did:
     * a smaller pool is still correct, just slower.
     */
    size_t started = 0;
    for (size_t i = 0; i < nthreads; i++) {
        if (pthread_create(&tp->threads[started], NULL, worker_main, tp) == 0) {
            started++;
        }
    }

    if (started == 0) {
        fprintf(stderr, "error: could not start any worker threads\n");
        pthread_mutex_destroy(&tp->lock);
        pthread_cond_destroy(&tp->work_ready);
        pthread_cond_destroy(&tp->all_idle);
        free(tp->threads);
        free(tp);
        return NULL;
    }

    tp->nthreads = started;
    return tp;
}

int threadpool_submit(threadpool_t *tp, tp_job_fn fn, void *arg)
{
    if (tp == NULL || fn == NULL) {
        return -1;
    }

    tp_task_t *task = malloc(sizeof(*task));
    if (task == NULL) {
        return -1;
    }
    task->fn = fn;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&tp->lock);

    /* Refuse new work once shutdown has begun. */
    if (tp->shutting_down) {
        pthread_mutex_unlock(&tp->lock);
        free(task);
        return -1;
    }

    if (tp->tail == NULL) {
        tp->head = task;
        tp->tail = task;
    } else {
        tp->tail->next = task;
        tp->tail = task;
    }
    tp->pending++;

    pthread_cond_signal(&tp->work_ready);
    pthread_mutex_unlock(&tp->lock);
    return 0;
}

void threadpool_wait(threadpool_t *tp)
{
    if (tp == NULL) {
        return;
    }

    pthread_mutex_lock(&tp->lock);
    while (tp->pending > 0) {
        pthread_cond_wait(&tp->all_idle, &tp->lock);
    }
    pthread_mutex_unlock(&tp->lock);
}

void threadpool_destroy(threadpool_t *tp)
{
    if (tp == NULL) {
        return;
    }

    /* Tell every worker to finish up, then wake them all. */
    pthread_mutex_lock(&tp->lock);
    tp->shutting_down = 1;
    pthread_cond_broadcast(&tp->work_ready);
    pthread_mutex_unlock(&tp->lock);

    for (size_t i = 0; i < tp->nthreads; i++) {
        pthread_join(tp->threads[i], NULL);
    }

    /* Drop anything left unrun (only possible if destroy skipped wait). */
    tp_task_t *task = tp->head;
    while (task != NULL) {
        tp_task_t *next = task->next;
        free(task);
        task = next;
    }

    pthread_mutex_destroy(&tp->lock);
    pthread_cond_destroy(&tp->work_ready);
    pthread_cond_destroy(&tp->all_idle);
    free(tp->threads);
    free(tp);
}
