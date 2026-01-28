#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("test");

void check_func(void) {
(void)&vm_flags_set;
}