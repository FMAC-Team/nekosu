#!/usr/bin/env python3
"""Generate a C header file from a C source file."""

import re
import sys
import os


BLACKLIST = [
    'uid_cap.c',
    'manager.c'
]

def _has_no_export_before(source: str, match_start: int) -> bool:
    """Return True if the line immediately preceding match_start is '// no export'."""
    preceding = source[:match_start]
    matches = list(re.finditer(r'//\s*no\s+export\s*$', preceding, re.MULTILINE))
    if not matches:
        return False
        
    last_comment = matches[-1]
    between = preceding[last_comment.end():]
    
    # If there is a blank line between the comment and the definition,
    # the comment is not attached to this definition.
    return not bool(re.search(r'\n[ \t]*\n', between))


def extract_defines(source: str) -> list[str]:
    results = []
    for m in re.finditer(
        r'([ \t]*#define[ \t]+\S+[^\\\n]*(?:\\\n[^\n]*)*)',
        source, re.MULTILINE
    ):
        if _has_no_export_before(source, m.start()):
            continue
        results.append(m.group(1).strip())
    return results


def extract_structs(source: str) -> list[str]:
    results = []
    pattern = re.compile(
        r'(?:typedef\s+)?struct\s+\w+\s*\{[^}]*\}(?:\s*\w+)?\s*;',
        re.DOTALL
    )
    for m in pattern.finditer(source):
        if _has_no_export_before(source, m.start()):
            continue
        results.append(m.group(0).strip())
    return results


def extract_public_functions(source: str) -> list[str]:
    pattern = re.compile(
        r'^'
        r'((?:[ \t]*//[^\n]*\n)*?)'
        r'((?:(?:static|inline)\s+)*)'
        r'((?:[a-zA-Z_]\w*(?:\s+|\s*\*\s*))+)'
        r'\s*(\w+)'
        r'\s*\(([^)]*)\)'
        r'\s*\n?\s*\{',
        re.MULTILINE
    )

    declarations = []
    for m in pattern.finditer(source):
        preceding_comments = m.group(1) or ''
        qualifiers         = m.group(2) or ''
        ret_type           = m.group(3).strip()
        name               = m.group(4).strip()
        params             = m.group(5).strip()

        if re.search(r'//\s*no\s+export', preceding_comments):
            continue
        if 'static' in qualifiers or 'inline' in qualifiers:
            continue
        if name == 'main':
            continue

        ret_type = re.sub(r'\s+', ' ', ret_type)
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

    lines = [
        f"#ifndef {guard_name}",
        f"#define {guard_name}",
        "",
    ]

    if defines:
        lines.extend(defines)
        lines.append("")

    if structs:
        for s in structs:
            lines.append(s)
            lines.append("")

    if functions:
        for decl in functions:
            lines.append(decl)
        lines.append("")

    lines.append(f"#endif /* {guard_name} */")
    return "\n".join(lines)


def is_blacklisted(c_path: str) -> bool:
    """Check if the file is in the blacklist."""
    basename = os.path.basename(c_path)
    return basename in BLACKLIST


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.c> [output.h]")
        sys.exit(1)

    c_path = sys.argv[1]
    
    if is_blacklisted(c_path):
        print(f"Skipping blacklisted file: {c_path}")
        sys.exit(0)

    if not os.path.exists(c_path):
        print(f"Error: {c_path} not found")
        sys.exit(1)

    h_path = (sys.argv[2] if len(sys.argv) >= 3
              else re.sub(r'\.c$', '.h', c_path))

    header = generate_header(c_path)
    with open(h_path, 'w') as f:
        f.write(header)
    print(f"Generated: {h_path}")


if __name__ == "__main__":
    main()