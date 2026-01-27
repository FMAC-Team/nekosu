#include <stdio.h>
#include <linux/module.h>
#include <linux/mm.h>

/* 列出你要检测的函数 */
#define FUNC_LIST \
    X(vma_set_flags) \
    X(get_user_pages)

int main(void) {
#define X(FUNC) \
    do { \
        int (*p)(void *) = (int (*)(void *)) &FUNC; \
        (void)p; \
        printf("#define HAVE_%s 1\n", #FUNC); \
    } while(0);

    FUNC_LIST
#undef X
    return 0;
}