/*
   3APA3A simplest proxy server
   (c) 2002-2026 by Vladimir Dubrovin <vlad@3proxy.org>

   please read License Agreement

*/

/* Counting semaphores for POSIX systems, built on a mutex and a condition
   variable: unnamed POSIX semaphores are not available everywhere (macOS)
   and have no timed wait there. Windows uses its own semaphores, see proxy.h. */

#include "proxy.h"

#ifndef _WIN32
/* macOS has CLOCK_MONOTONIC but no pthread_condattr_setclock(); a relative
   wait is used there instead, which the system time does not affect either */
#if defined(CLOCK_MONOTONIC) && !defined(__APPLE__)
#define SEM_MONOTONIC
#endif

int _3proxy_sem_init_f(_3proxy_sem_t *sem, unsigned count, unsigned maxcount, int timed){
	int res;

	sem->count = count;
	sem->maxcount = maxcount;
	sem->monotonic = 0;
	if(pthread_mutex_init(&sem->mutex, NULL)) return 1;
#ifdef SEM_MONOTONIC
	if(timed){
		pthread_condattr_t attr;

		if(!pthread_condattr_init(&attr)){
			if(!pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)) sem->monotonic = 1;
			res = pthread_cond_init(&sem->cond, &attr);
			pthread_condattr_destroy(&attr);
		}
		else res = pthread_cond_init(&sem->cond, NULL);
	}
	else
#endif
	res = pthread_cond_init(&sem->cond, NULL);
	if(res){
		pthread_mutex_destroy(&sem->mutex);
		return 1;
	}
	return 0;
}

void _3proxy_sem_lock_f(_3proxy_sem_t *sem){
	pthread_mutex_lock(&sem->mutex);
	while(!sem->count) pthread_cond_wait(&sem->cond, &sem->mutex);
	sem->count--;
	pthread_mutex_unlock(&sem->mutex);
}

/* Returns 0 with the semaphore taken, nonzero if ms passed first. */
int _3proxy_sem_timedlock_f(_3proxy_sem_t *sem, unsigned ms){
	struct timespec ts;
	int res = 0;

#ifdef __APPLE__
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000;
	pthread_mutex_lock(&sem->mutex);
	while(!sem->count && !res) res = pthread_cond_timedwait_relative_np(&sem->cond, &sem->mutex, &ts);
#else
	/* the deadline is on the clock the condition variable was set up with */
#ifdef SEM_MONOTONIC
	if(sem->monotonic) clock_gettime(CLOCK_MONOTONIC, &ts);
	else
#endif
	{
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000;
	}
	ts.tv_sec += ms / 1000;
	ts.tv_nsec += (long)(ms % 1000) * 1000000;
	if(ts.tv_nsec >= 1000000000){
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}
	pthread_mutex_lock(&sem->mutex);
	while(!sem->count && !res) res = pthread_cond_timedwait(&sem->cond, &sem->mutex, &ts);
#endif
	if(sem->count){
		sem->count--;
		res = 0;
	}
	pthread_mutex_unlock(&sem->mutex);
	return res;
}

void _3proxy_sem_unlock_f(_3proxy_sem_t *sem){
	pthread_mutex_lock(&sem->mutex);
	if(sem->count < sem->maxcount){
		sem->count++;
		pthread_cond_signal(&sem->cond);
	}
	pthread_mutex_unlock(&sem->mutex);
}

void _3proxy_sem_destroy_f(_3proxy_sem_t *sem){
	pthread_cond_destroy(&sem->cond);
	pthread_mutex_destroy(&sem->mutex);
}
#endif
