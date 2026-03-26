#!/usr/bin/env python3
"""Generate a C header file from a C source file."""

import re
import sys
import os

# Marker comment on the line immediately before a definition to suppress export.
NO_EXPORT_RE = re.compile(r'//\s*no\s+export\s*[\r\n]')


def extract_defines(source: str) -> list[str]:
    results = []
    # Walk matches; check whether the character just before the match is
    # preceded by a no-export comment on the previous line.
    for m in re.finditer(r'([ \t]*#define[ \t]+\S+[^\\\n]*(?:\\\n[^\n]*)*)',
                         source, re.MULTILINE):
        start = m.start()
        preceding = source[:start]
        # Check if the line immediately before is a no-export comment.
        prev_line_match = re.search(r'//\s*no\s+export\s*$', preceding,
                                    re.MULTILINE)
        if prev_line_match:
            # Make sure there's no blank line between the comment and define.
            between = preceding[prev_line_match.end():]
            if not re.search(r'\n[ \t]*\n', between):
                continue
        results.append(m.group(1).strip())
    return results


def extract_structs(source: str) -> list[str]:
    results = []
    pattern = re.compile(
        r'(struct\s+\w+\s*\{[^}]*\}\s*;)',
        re.DOTALL
    )
    for m in pattern.finditer(source):
        start = m.start()
        preceding = source[:start]
        prev_line = re.search(r'//\s*no\s+export\s*$', preceding, re.MULTILINE)
        if prev_line:
            between = preceding[prev_line.end():]
            if not re.search(r'\n[ \t]*\n', between):
                continue
        results.append(m.group(1).strip())
    return results


def extract_public_functions(source: str) -> list[str]:
    # Match: [no-export comment\n] [static] return-type func-name(params) {
    # Return type may be multi-word (e.g. "unsigned long", "long __must_check").
    # We anchor on the opening brace so we don't match declarations.
    pattern = re.compile(
        r'^'
        r'((?:[ \t]*//[^\n]*\n)*?)'        # group 1: optional preceding comments
        r'((?:static|inline)\s+)*'          # group 2: storage qualifiers (skip)
        r'((?:[a-zA-Z_]\w*(?:\s+|\s*\*\s*))+)'  # group 3: return type
        r'\s*(\w+)'                          # group 4: function name
        r'\s*\(([^)]*)\)'                    # group 5: params
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

        if NO_EXPORT_RE.search(preceding_comments):
            continue
        if 'static' in qualifiers or 'inline' in qualifiers:
            continue
        if name == 'main':
            continue

        # Normalise multiple spaces in return type.
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

    lines = []
    lines.append(f"#ifndef {guard_name}")
    lines.append(f"#define {guard_name}")
    lines.append("")

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


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.c> [output.h]")
        sys.exit(1)

    c_path = sys.argv[1]
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