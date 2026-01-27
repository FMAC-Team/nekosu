#!/bin/bash
CONFIG_H="$1"
CC="$2"
CFLAGS="$3" 

CHECK_FUNCS=("printk" "vma_set_flags" "get_user_pages")

# 1. 提取内核源码路径 (KDIR)
# 尝试从 CFLAGS 提取，如果提取不到，尝试从当前环境推断
KDIR=$(echo "$CFLAGS" | grep -o '\-I[^ ]*' | head -1 | sed 's|-I||' | sed 's|/include$||')

# 调试信息
echo "KDIR detected: $KDIR"

echo "#ifndef _NKSU_FUNC_CHECK_H" > "$CONFIG_H"
echo "#define _NKSU_FUNC_CHECK_H" >> "$CONFIG_H"

echo "Searching for function definitions in kernel headers..."

for FUNC in "${CHECK_FUNCS[@]}"; do
    # 在内核 include 目录下搜索函数声明或宏定义
    # 逻辑：在 KDIR/include 及其子目录中搜索包含全字的函数名
    # 我们搜索常见的定义特征，如 "FUNC(" 或 "SYMBOL_GPL(FUNC)"
    
    FOUND=0
    if [ -d "$KDIR/include" ]; then
        # 搜索是否在头文件中有声明，或者是否有导出符号
        if grep -rqw "$FUNC" "$KDIR/include" "$KDIR/arch" 2>/dev/null; then
            FOUND=1
        fi
    fi

    if [ $FOUND -eq 1 ]; then
        echo "  [+] found: $FUNC"
        echo "#define HAVE_${FUNC} 1" >> "$CONFIG_H"
    else
        echo "  [-] missing: $FUNC"
        echo "#define HAVE_${FUNC} 0" >> "$CONFIG_H"
    fi
done

echo "#endif" >> "$CONFIG_H"
echo "Generated $CONFIG_H"
