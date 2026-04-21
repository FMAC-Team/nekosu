#include <linux/types.h>

#define NKSU_MARK_AUTHORIZED  BIT(0)
#define NKSU_MARK_ROOT        BIT(1)
#define NKSU_MARK_SU          BIT(2)

#if LINUX_VERSION_CODE > KERNEL_VERSION(6, 12, 0)
#  define NKSU_KABI_FIELD __kabi_reserved1
#else
#  define NKSU_KABI_FIELD android_kabi_reserved1
#endif

int  nksu_kabi_field_check(void);
u32  nksu_task_get_mark(struct task_struct *task);
bool nksu_task_check_mark(struct task_struct *task, u32 mark);
void nksu_task_set_mark(struct task_struct *task, u32 mark);
void nksu_task_clear_mark(struct task_struct *task, u32 mark);
int  nksu_task_mark_init(void);
void nksu_task_mark_exit(void);

#define nksu_current_check_mark(mark) \
    nksu_task_check_mark(current, mark)
#define nksu_current_set_mark(mark) \
    nksu_task_set_mark(current, mark)
#define nksu_current_clear_mark(mark) \
    nksu_task_clear_mark(current, mark)

static __always_inline u32 *nksu_mark_ptr(struct task_struct *task)
{
	return (u32 *)&task->NKSU_KABI_FIELD;
}

static __always_inline u32 nksu_task_get_mark_inline(struct task_struct *task)
{
    return READ_ONCE(*nksu_mark_ptr(task));
}

static __always_inline bool nksu_task_check_mark_inline(struct task_struct *task, u32 mark)
{
    return (READ_ONCE(*nksu_mark_ptr(task)) & mark) == mark;
}

static __always_inline u32 nksu_current_get_mark(void)
{
    return READ_ONCE(*nksu_mark_ptr(current));
}

static __always_inline bool nksu_current_check_mark(u32 mark)
{
    return (READ_ONCE(*nksu_mark_ptr(current)) & mark) == mark;
}