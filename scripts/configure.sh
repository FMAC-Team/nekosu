#!/bin/bash
CONFIG_H="$1"
CC="$2"
CFLAGS="$3" 

CHECK_FUNCS=( "vma_set_flags" "get_user_pages")

KDIR=$(echo "$CFLAGS" | grep -o '\-I[^ ]*' | head -1 | sed 's|-I||' | sed 's|/include$||')

echo "KDIR detected: $KDIR"

echo "#ifndef _NKSU_FUNC_CHECK_H" > "$CONFIG_H"
echo "#define _NKSU_FUNC_CHECK_H" >> "$CONFIG_H"

echo "Searching for function definitions in kernel headers..."

for FUNC in "${CHECK_FUNCS[@]}"; do
    FOUND=0
    if [ -d "$KDIR/include" ]; then
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
