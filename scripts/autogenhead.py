#!/usr/bin/env python3
"""Generate a C header file from a C source file."""

import re
import sys
import os

NO_EXPORT = re.compile(r'//\s*no\s+export\s*\n')


def extract_defines(source: str) -> list[str]:
    results = []
    for m in re.finditer(r'(' + NO_EXPORT.pattern + r')?(\s*#define\s+(\S+).*)', source):
        if m.group(1):
            continue
        results.append(m.group(2).strip())
    return results


def extract_structs(source: str) -> list[str]:
    results = []
    pattern = re.compile(
        r'(' + NO_EXPORT.pattern + r')?'
        r'(struct\s+(\w+)\s*\{[^}]*\}\s*;)',
        re.DOTALL
    )
    for m in pattern.finditer(source):
        if m.group(1):
            continue
        results.append(m.group(2).strip())
    return results


def extract_public_functions(source: str) -> list[str]:
    pattern = re.compile(
        r'(' + NO_EXPORT.pattern + r')?'
        r'(static\s+)?'
        r'([a-zA-Z_][\w\s\*]*?)'
        r'\s+(\w+)'
        r'\s*\(([^)]*)\)'
        r'\s*\n?\s*\{',
        re.MULTILINE
    )

    declarations = []
    for m in pattern.finditer(source):
        no_export = m.group(1)
        is_static = m.group(2)
        ret_type  = m.group(3).strip()
        name      = m.group(4).strip()
        params    = m.group(5).strip()

        if no_export or is_static:
            continue
        if name == 'main':
            continue

        declarations.append(f"{ret_type} {name}({params});")

    return declarations


def generate_header(c_path: str) -> str:
    with open(c_path, 'r') as f:
        source = f.read()

    basename   = os.path.basename(c_path)
    stem       = os.path.splitext(basename)[0]
    guard_name = re.sub(r'[^a-zA-Z0-9]', '_', stem).upper() + '_H'

    defines   = extract_defines(source)
    structs   = extract_structs(source)
    functions = extract_public_functions(source)

    lines = []
    lines.append(f"#ifndef {guard_name}")
    lines.append(f"#define {guard_name}")
    lines.append("")

    if defines:
        lines.extend(defines)
        lines.append("")

    if structs:
        for struct in structs:
            lines.append(struct)
            lines.append("")

    if functions:
        for decl in functions:
            lines.append(decl)
        lines.append("")

    lines.append(f"#endif /* {guard_name} */")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.c> [output.h]")
        sys.exit(1)

    c_path = sys.argv[1]
    if not os.path.exists(c_path):
        print(f"Error: {c_path} not found")
        sys.exit(1)

    h_path = sys.argv[2] if len(sys.argv) >= 3 else re.sub(r'\.c$', '.h', c_path)

    header = generate_header(c_path)

    with open(h_path, 'w') as f:
        f.write(header)

    print(f"Generated: {h_path}")


if __name__ == "__main__":
    main()