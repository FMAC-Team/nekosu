#define NKSU_MARK_AUTHORIZED  BIT(0)
#define NKSU_MARK_ROOT        BIT(1)
#define NKSU_MARK_SU          BIT(2)

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
