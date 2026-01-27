#!/bin/bash
CONFIG_H="$1"
CC="$2"
CFLAGS="$3" 

CHECK_FUNCS=("printk" "vma_set_flags" "get_user_pages")

# 提取 KDIR 和 ARCH
KDIR=$(echo "$CFLAGS" | grep -o '\-I[^ ]*' | head -1 | sed 's|-I||' | sed 's|/include$||')
ARCH=$(echo "$CFLAGS" | grep -o 'arch/[^/]*' | head -1 | cut -d'/' -f2)

# 完善内核搜索路径
KERNEL_CFLAGS="$CFLAGS \
    -I${KDIR}/include/generated \
    -I${KDIR}/arch/${ARCH}/include/generated \
    -I${KDIR}/include/uapi \
    -I${KDIR}/arch/${ARCH}/include/uapi \
    -D__KERNEL__"

echo "#ifndef _NKSU_FUNC_CHECK_H" > "$CONFIG_H"
echo "#define _NKSU_FUNC_CHECK_H" >> "$CONFIG_H"

echo "Searching for function definitions via Preprocessor..."

for FUNC in "${CHECK_FUNCS[@]}"; do
    # 修复点：将 -qW 改为 -qw
    # 增加了一个简单的正则表达式，确保匹配的是函数名或宏名
    cat <<EOF | $CC ${KERNEL_CFLAGS} -xc - -E -P 2>/dev/null | grep -qw "$FUNC"
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
EOF

    if [ $? -eq 0 ]; then
        echo "  [+] defined: $FUNC"
        echo "#define HAVE_${FUNC} 1" >> "$CONFIG_H"
    else
        echo "  [-] not found: $FUNC"
        echo "#define HAVE_${FUNC} 0" >> "$CONFIG_H"
    fi
done

echo "#endif" >> "$CONFIG_H"
echo "Generated $CONFIG_H"
