#!/bin/bash
CONFIG_H="$1"
CC="$2"
CFLAGS="$3" 

CHECK_FUNCS=("printk" "vma_set_flags" "get_user_pages")

echo "CC $CC"
echo "CFLAGS $CFLAGS"

KDIR=$(echo "$CFLAGS" | grep -o '\-I[^ ]*' | head -1 | sed 's|-I||' | sed 's|/include$||')
ARCH=$(echo "$CFLAGS" | grep -o 'arch/[^/]*' | head -1 | cut -d'/' -f2)

echo "#ifndef _NKSU_FUNC_CHECK_H" > "$CONFIG_H"
echo "#define _NKSU_FUNC_CHECK_H" >> "$CONFIG_H"

echo "Checking kernel functions..."

for FUNC in "${CHECK_FUNCS[@]}"; do
    
    cat <<EOF | $CC $CFLAGS -I${KDIR}/include/generated -I${KDIR}/include/generated/uapi -I${KDIR}/arch/${ARCH}/include/generated -I${KDIR}/arch/${ARCH}/include/generated/uapi -Wno-unused -Werror=implicit-function-declaration -xc - -c -o /dev/null 2>&1
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

void check_symbol_existence(void) {
    (void)${FUNC};
}
EOF

    if [ $? -eq 0 ]; then
        echo "  [+] found: $FUNC"
        echo "#define HAVE_$FUNC 1" >> "$CONFIG_H"
    else
        echo "  [-] missing: $FUNC"
        echo "/* #undef HAVE_$FUNC */" >> "$CONFIG_H"
    fi
done

echo "#endif" >> "$CONFIG_H"

echo "Generated $CONFIG_H"