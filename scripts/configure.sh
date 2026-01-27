#!/bin/bash
# 用法: ./check_funcs.sh /path/to/config.h
CONFIG_H="$1"
CC="${CC:-cc}"
CFLAGS="${KBUILD_CFLAGS:-}" 

CHECK_FUNCS=("vma_set_flags" "get_user_pages")

CODE="#include <linux/module.h>\n#include <linux/mm.h>\n"
for f in "${CHECK_FUNCS[@]}"; do
    CODE="${CODE}static void check_$f(void) { (void)$f; }\n"
done

echo -e "$CODE" | $CC $CFLAGS -Wall -Werror -xc - -c -o /dev/null >/dev/null 2>&1

if [ $? -eq 0 ]; then
    > "$CONFIG_H"
    for f in "${CHECK_FUNCS[@]}"; do
        echo "#define HAVE_$f 1" >> "$CONFIG_H"
    done
else
    echo "/* No functions detected */" > "$CONFIG_H"
fi

echo "Generated $CONFIG_H"
cat $CONFIG_H