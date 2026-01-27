#!/bin/bash
CONFIG_H="$1"
CC="$2"
CFLAGS="$3" 

CHECK_FUNCS=("vma_flags_set" "get_user_pages")

KDIR=$(echo "$CFLAGS" | grep -o '\-I[^ ]*' | head -1 | sed 's|-I||' | sed 's|/include$||')
ARCH=$(echo "$CFLAGS" | grep -o 'arch/[^/]*' | head -1 | cut -d'/' -f2)

echo "KDIR detected: $KDIR"
echo "ARCH detected: $ARCH"

echo "#ifndef _NKSU_FUNC_CHECK_H" > "$CONFIG_H"
echo "#define _NKSU_FUNC_CHECK_H" >> "$CONFIG_H"
echo "" >> "$CONFIG_H"

echo "Searching for function definitions in kernel headers..."

for FUNC in "${CHECK_FUNCS[@]}"; do
    FOUND=0
    
    SEARCH_PATHS=(
        "$KDIR/include/linux"
        "$KDIR/include/asm-generic"
        "$KDIR/arch/${ARCH}/include"
    )
    
    # 匹配：
    # - #define vma_flags_set
    # - static inline ... vma_flags_set(
    # - extern ... vma_flags_set(
    # - void vma_flags_set(
    for path in "${SEARCH_PATHS[@]}"; do
        if [ -d "$path" ]; then
            # 使用更精确的正则表达式
            if grep -rE "(^|[[:space:]])#define[[:space:]]+${FUNC}[[:space:]\(]|" \
                        -e "(static[[:space:]]+)?inline[[:space:]]+.*[[:space:]]${FUNC}[[:space:]]*\(|" \
                        -e "^[[:space:]]*(extern[[:space:]]+)?.*[[:space:]]${FUNC}[[:space:]]*\(" \
                        "$path" 2>/dev/null | grep -v "^Binary" | head -1 > /dev/null; then
                FOUND=1
                # 显示找到的位置（调试用）
                FOUND_IN=$(grep -rl "$FUNC" "$path" 2>/dev/null | head -1)
                break
            fi
        fi
    done
    
    if [ $FOUND -eq 1 ]; then
        echo "  [+] found: $FUNC${FOUND_IN:+ in ${FOUND_IN#$KDIR/}}"
        echo "#define HAVE_${FUNC} 1" >> "$CONFIG_H"
    else
        echo "  [-] missing: $FUNC"
        echo "#define HAVE_${FUNC} 0" >> "$CONFIG_H"
    fi
done

echo "" >> "$CONFIG_H"
echo "#endif /* _NKSU_FUNC_CHECK_H */" >> "$CONFIG_H"

echo "Generated $CONFIG_H"