#define _BSD_SOURCE
#include <re.h>
#include <avs_log.h>
#include <avs_service.h>
#include <pthread.h>
#include <unistd.h>


#define TIMEOUT_WORKER 20

struct worker_task {
	enum worker_task_id id;
	worker_task_h *h;
	void *arg;

	struct le le;
};

struct worker {
	pthread_t tid;
	bool running;
	int id;

	//struct mqueue *mq;
	struct tmr tmr;
	bool ready;

	struct le le;

	struct lock *lock;
	struct list taskl;
};

struct work_balancer {
	struct worker *main;
	struct worker **v;
	size_t c;
};

static struct work_balancer *workb = NULL;

static int push_task(struct worker *w, enum worker_task_id tid,
		     worker_task_h *taskh, void *arg);


static void workb_destructor(void *arg)
{
	struct work_balancer *wb = arg;
	size_t i;

#if 1
	for(i = 0; i < wb->c; ++i) {
		wb->v[i] = mem_deref(wb->v[i]);
	}
#endif
	mem_deref(wb->v);

	/* Close down main thread */
	info("workb_destructor: closing main\n");
	workb->main->running = false;
	//push_task(workb->main, WORKER_TASK_DEREF, NULL, NULL);
	mem_deref(workb->main);
}


static void worker_destructor(void *arg)
{
	struct worker *w = arg;

	info("worker_destructor: id=%d\n", w->id);
	if (w->id > 0)
		workb->v[w->id - 1] = (struct worker *)NULL;

	w->running = false;
	tmr_cancel(&w->tmr);
	lock_write_get(w->lock);
	list_flush(&w->taskl);
	lock_rel(w->lock);
	mem_deref(w->lock);
}

static bool perform_task(struct worker *w, struct worker_task *task)
{
	bool running = true; 
	
	switch(task->id) {
	case WORKER_TASK_RUN:
		running = true;
		if (task && task->h)
			task->h(task->arg);
		break;
		
	case WORKER_TASK_QUIT:
		info("worker_thread: cancelling wid=%d\n", w->id);
		running = false;
		re_cancel();
		break;

	case WORKER_TASK_DEREF:
		info("worker_thread: destroying main\n");
		running = false;
		mem_deref(w);
		break;

	default:
		break;
	}

	return running;
}

#if 0
static void task_handler(int id, void *data, void *arg)
{
	struct worker_task *task = data;
	struct worker *w = arg;

	(void)data;


	perform_task(w, task);	
}
#endif

static void worker_timeout_handler(void *arg)
{
	struct worker *w = arg;
	struct le *le = NULL;
	bool running = true;

	//info("worker_timeout: w(%p): %d\n", w, w->id);
	
	do {
		struct worker_task *task = NULL;

		lock_write_get(w->lock);
		le = w->taskl.head;
		if (le) {
			task = le->data;
			/* Ref the task so we are sure nothing will
			 * destruct it when the lock is released
			 */
			task = mem_ref(task);
			list_unlink(le);
		}
		lock_rel(w->lock);
		if (task) {
			running = perform_task(w, task);
			mem_deref(task);
		}
		mem_deref(task);
	}
	while(le && running);

	if (running)
		tmr_start(&w->tmr, TIMEOUT_WORKER, worker_timeout_handler, w);	
}

static void *worker_thread(void *arg)
{
	struct worker *w = arg;
	
	info("worker(%p): thread: %p id: %d started\n",
	     w, pthread_self(), w->id);
	
	re_thread_init();

	w->ready = true;
	tmr_start(&w->tmr, TIMEOUT_WORKER, worker_timeout_handler, w);	
	re_main(NULL);
	
	info("worker_thread: id: %d ended\n", w->id);

	mem_deref(w);

	return NULL;
}

static void task_destructor(void *arg)
{
	struct worker_task *task = arg;

	mem_deref(task->arg);
}

struct worker *worker_get(const char *id)
{
	struct worker *w;
	uint32_t key;
	int wid;
	
	key = hash_joaat_str_ci(id);
	wid = (int)(key % (uint32_t)workb->c);

	w = workb->v[wid];

	return w;
}

struct worker *worker_main(void)
{
	return workb->main;
}

static int push_task(struct worker *w, enum worker_task_id tid,
		     worker_task_h *taskh, void *arg)
{
	struct worker_task *task;
	int err = 0;

	task = mem_zalloc(sizeof(*task), task_destructor);
	if (!task)
		return ENOMEM;

	task->id = tid;
	task->h = taskh;
	if (arg)
		task->arg = mem_ref(arg);

	//err = mqueue_push(mq, tid, task);
	lock_write_get(w->lock);
	list_append(&w->taskl, &task->le, task);
	lock_rel(w->lock);

	//err = mqueue_push(w->mq, tid, NULL);

	return err;
}

int worker_assign_main(worker_task_h *taskh, void *arg)
{
	return push_task(workb->main, WORKER_TASK_RUN, taskh, arg);
}


int worker_assign_task(struct worker *w,
		       worker_task_h *taskh,
		       void *arg)
{
	int err = 0;

	if (!w)
		return EINVAL;

	err = push_task(w, WORKER_TASK_RUN, taskh, arg);
	
	return err;
}

static struct worker *alloc_worker(int id, bool is_main)
{
	struct worker *worker = NULL;
	int err = 0;
	
	worker = mem_zalloc(sizeof(*worker), worker_destructor);
	if (!worker) {
		err = ENOMEM;
		goto out;
	}

	worker->id = id;
	worker->running = true;
	tmr_init(&worker->tmr);
	list_init(&worker->taskl);
	err = lock_alloc(&worker->lock);
	if (err)
		goto out;

	if (is_main) {
		worker->ready = true;
		tmr_start(&worker->tmr, TIMEOUT_WORKER,
			  worker_timeout_handler, worker);
	}
	else {
		err = pthread_create(&worker->tid, NULL, worker_thread, worker);
		if (err)
			goto out;


		/* Wait for worker to become ready */
		while(!worker->ready) {
			usleep(10000);
		}
		info("worker(%p): %d ready\n", worker, worker->id);
	}
 out:
	if (err)
		worker = mem_deref(worker);

	return worker;
}

int worker_init(void)
{
	int nworkers;
	int err = 0;
	int i;

	nworkers = avs_service_worker_count();
	
	if (!nworkers)
		return EINVAL;

	workb = mem_zalloc(sizeof(*workb), workb_destructor);
	if (!workb) {
		err = ENOMEM;
		goto out;
	}
	//err = mqueue_alloc(&workb->q, task_handler, NULL);
	//if (err)
	//	goto out;

	workb->v = mem_zalloc(nworkers * sizeof(struct worker *), NULL);
	if (!workb->v) {
		err = ENOMEM;
		goto out;
	}

	workb->main = alloc_worker(0, true);
	if (!workb->main) {
		err = ENOMEM;
		goto out;
	}
	for(i = 0; i < nworkers; ++i) {
		struct worker *worker;
		
		worker = alloc_worker(i + 1, false);
		if (!worker) {
			err = ENOMEM;
			goto out;
		}
		else {
			workb->v[i] = worker;
			workb->c++;
		}
	}
	
 out:
	if (err)
		workb = mem_deref(workb);

	return err;
}


void worker_close(void)
{
	size_t i;
	int err;

	for (i = 0; i < workb->c; ++i) {
		struct worker *w = workb->v[i];
		pthread_t tid;

		if (!w)
			continue;

		tid = w->tid;
		//err = mqueue_push(w->mq, WORKER_TASK_QUIT, NULL);
		info("worker_close wid=%d\n", w->id);
		err = push_task(w, WORKER_TASK_QUIT, NULL, NULL);
		workb->v[i] = NULL;
		if (!err) {
			pthread_join(tid, NULL);
			
			/* when the worker thread exists, it will
			 * deref its worker object
			 */
		}			
	}

	workb = mem_deref(workb);
}

void *worker_tid(struct worker *w)
{
	return w ? (void*)w->tid : NULL;
}
