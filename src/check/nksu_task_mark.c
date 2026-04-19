#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <fmac.h>

#define NKSU_KABI_MAGIC      0xFAC0FAC0ULL
#define NKSU_SAMPLE_COUNT    16
#define NKSU_NONZERO_THRESH  4

static __always_inline u32 *nksu_mark_ptr(struct task_struct *task)
{
    return (u32 *)&task->android_kabi_reserved1;
}

static int nksu_kabi_sample_nonzero(void)
{
    struct task_struct *task;
    int nonzero = 0, total = 0;

    rcu_read_lock();
    for_each_process(task) {
        if (total >= NKSU_SAMPLE_COUNT)
            break;
        if (READ_ONCE(*nksu_mark_ptr(task)) != 0)
            nonzero++;
        total++;
    }
    rcu_read_unlock();

    return nonzero;
}

static bool nksu_kabi_rw_check(void)
{
    u32 *ptr = nksu_mark_ptr(current);
    u32 saved = READ_ONCE(*ptr);

    WRITE_ONCE(*ptr, (u32)NKSU_KABI_MAGIC);
    barrier();
    if (READ_ONCE(*ptr) != (u32)NKSU_KABI_MAGIC) {
        WRITE_ONCE(*ptr, saved);
        return false;
    }
    WRITE_ONCE(*ptr, saved);
    return true;
}

int nksu_kabi_field_check(void)
{
    int nonzero;

    if (!nksu_kabi_rw_check()) {
        pr_err("nksu: android_kabi_reserved1 rw check failed\n");
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
    nksu_task_clear_mark(child, NKSU_MARK_AUTHORIZED |
                                NKSU_MARK_ROOT       |
                                NKSU_MARK_SU);
}

int nksu_task_mark_init(void)
{
    int ret;

    ret = nksu_kabi_field_check();
    if (ret)
        return ret;

    return register_trace_sched_process_fork(nksu_on_fork, NULL);
}

void nksu_task_mark_exit(void)
{
    unregister_trace_sched_process_fork(nksu_on_fork, NULL);
}
