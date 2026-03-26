#!/usr/bin/env python3
"""Generate a C header file from a C source file."""

import re
import sys
import os


def extract_defines(source: str) -> list[str]:
    return re.findall(r'^\s*#define\s+\S+.*', source, re.MULTILINE)


def extract_structs(source: str) -> list[str]:
    results = []
    pattern = re.compile(r'(struct\s+\w+\s*\{[^}]*\}\s*;)', re.DOTALL)
    for match in pattern.finditer(source):
        results.append(match.group(1).strip())
    return results


def extract_public_functions(source: str) -> list[str]:
    pattern = re.compile(
        r'^(?!.*\bstatic\b)'
        r'([a-zA-Z_][\w\s\*]*?)'
        r'\s+(\w+)'
        r'\s*\(([^)]*)\)'
        r'\s*\{',
        re.MULTILINE
    )

    declarations = []
    for match in pattern.finditer(source):
        ret_type = match.group(1).strip()
        name     = match.group(2).strip()
        params   = match.group(3).strip()

        if name == 'main':
            continue

        declarations.append(f"{ret_type} {name}({params});")

    return declarations


def generate_header(c_path: str) -> str:
    with open(c_path, 'r') as f:
        source = f.read()

    basename   = os.path.basename(c_path)
    guard_name = re.sub(r'[^a-zA-Z0-9]', '_', basename).upper()
    guard_name = re.sub(r'_C_$', '_H_', guard_name)

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