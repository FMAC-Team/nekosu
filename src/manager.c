#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>

void get_apk_path(struct task_struct *task) {
  struct file *exe;
  char *tmp, *buf;

  if (!task || !task->mm)
    return;

  exe = task->mm->exe_file;
  if (!exe)
    return;

  buf = (char *)__get_free_page(GFP_KERNEL);
  if (!buf)
    return;

  tmp = d_path(&exe->f_path, buf, PAGE_SIZE);
  if (!IS_ERR(tmp)) {
    printk(KERN_INFO "[ksu] APK Path: %s\n", tmp);
  } else {
    printk(KERN_ERR "[ksu] d_path failed: %ld\n", PTR_ERR(tmp));
  }

  free_page((unsigned long)buf);
}