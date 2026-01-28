#include <linux/printk.h>

MODULE_LICENSE("test")

void check_printk(void){
(void)printk(KERN_INFO "test\n");
}