// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/android_kabi.h>
#include <linux/version.h>
#include <trace/events/sched.h>

#include <fmac.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 12, 0)
#  define NKSU_KABI_FIELD __kabi_reserved1
#else
#  define NKSU_KABI_FIELD android_kabi_reserved1
#endif

#define NKSU_KABI_MAGIC      ((u32)0xFAC0FAC0U)
#define NKSU_SAMPLE_COUNT    16
#define NKSU_NONZERO_THRESH  4
#define NKSU_SAMPLE_PID_MIN  100

#define NKSU_FORK_CLEAR_MASK \
	(NKSU_MARK_AUTHORIZED | NKSU_MARK_ROOT | NKSU_MARK_SU)

static bool nksu_kabi_offset_check(void)
{
	u64 dummy = 0;
	u32 *ptr = (u32 *)&dummy;

	WRITE_ONCE(*ptr, NKSU_KABI_MAGIC);
	return READ_ONCE(*ptr) == NKSU_KABI_MAGIC;
}

static int nksu_kabi_sample_nonzero(void)
{
	struct task_struct *task;
	int nonzero = 0, total = 0;

	rcu_read_lock();
	for_each_process(task) {
		if (task->pid < NKSU_SAMPLE_PID_MIN)
			continue;
		if (READ_ONCE(*nksu_mark_ptr(task)) != 0)
			nonzero++;
		if (++total >= NKSU_SAMPLE_COUNT)
			break;
	}
	rcu_read_unlock();

	return nonzero;
}

int nksu_kabi_field_check(void)
{
	int nonzero;

	if (!nksu_kabi_offset_check()) {
		pr_err("nksu: kabi field offset check failed\n");
		return -EBUSY;
	}

	nonzero = nksu_kabi_sample_nonzero();
	if (nonzero > NKSU_NONZERO_THRESH) {
		pr_err("nksu: android_kabi_reserved1 may be in use "
		       "(%d/%d sampled tasks non-zero)\n",
		       nonzero, NKSU_SAMPLE_COUNT);
		return -EBUSY;
	}

	pr_info("nksu: android_kabi_reserved1 available "
		"(%d/%d sampled tasks non-zero)\n",
		nonzero, NKSU_SAMPLE_COUNT);
	return 0;
}

u32 nksu_task_get_mark(struct task_struct *task)
{
	return READ_ONCE(*nksu_mark_ptr(task));
}

bool nksu_task_check_mark(struct task_struct *task, u32 mark)
{
	return (READ_ONCE(*nksu_mark_ptr(task)) & mark) == mark;
}

void nksu_task_set_mark(struct task_struct *task, u32 mark)
{
	u32 *ptr = nksu_mark_ptr(task);
	u32 old, new;

	do {
		old = READ_ONCE(*ptr);
		new = old | mark;
	} while (cmpxchg(ptr, old, new) != old);
}

void nksu_task_clear_mark(struct task_struct *task, u32 mark)
{
	u32 *ptr = nksu_mark_ptr(task);
	u32 old, new;

	do {
		old = READ_ONCE(*ptr);
		new = old & ~mark;
	} while (cmpxchg(ptr, old, new) != old);
}

static void nksu_on_fork(void *data, struct task_struct *parent,
			 struct task_struct *child)
{
	u32 cur = READ_ONCE(*nksu_mark_ptr(child));

	if (cur & NKSU_FORK_CLEAR_MASK)
		WRITE_ONCE(*nksu_mark_ptr(child), cur & ~NKSU_FORK_CLEAR_MASK);
}

int nksu_task_mark_init(void)
{
	int ret;

	ret = nksu_kabi_field_check();
	if (ret)
		return ret;

	ret = register_trace_sched_process_fork(nksu_on_fork, NULL);
	if (ret)
		pr_err("nksu: register sched_process_fork failed: %d\n", ret);

	return ret;
}

void nksu_task_mark_exit(void)
{
	unregister_trace_sched_process_fork(nksu_on_fork, NULL);
}