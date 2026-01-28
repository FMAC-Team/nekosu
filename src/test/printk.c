#include <linux/printk.h>

void check_printk(void){
(void)printk(KERN_INFO "test\n");
}