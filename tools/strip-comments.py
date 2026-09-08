#!/usr/bin/env python3
"""Remove comments from Rust source.

Scans each file as Rust tokens rather than matching patterns, so text that only
looks like a comment is left alone: `"http://host"` keeps its `//`, a raw string
`r#"/* not a comment */"#` keeps its body, and `&'a str` is read as a lifetime
rather than an unterminated character literal. Nested block comments are counted
to their matching close, as rustc counts them.

Removed: line comments (`//`), block comments (`/* */`), and by default the doc
comments `///`, `//!`, `/** */` and `/*! */`. `#[doc = "..."]` is an attribute,
not a comment, and is always left in place.

A line left blank by removing a whole-line comment is dropped, as is a blank
line the removal orphaned at the top of a file or doubled mid-file. A comment
after code on the same line leaves the code with its trailing space trimmed.

Prints what it would change and exits without writing unless --write is given.

usage:
  tools/strip-comments.py [PATH ...]              # report only
  tools/strip-comments.py --write [PATH ...]      # rewrite in place
  tools/strip-comments.py --write --keep-doc .    # keep /// //! /** */ /*! */
Paths default to the current directory. A directory is searched for *.rs,
skipping target/ and .git/.
"""

import argparse
import os
import re
import sys

RAW_START = re.compile(r'(?:b|c)?r(#*)"')
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def strip(src: str, keep_doc: bool = False) -> str:
    """Return `src` with its comments removed."""
    out = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]

        # Raw string: r"..", br#".."#, cr##".."## - no escapes inside, so the
        # close is the quote followed by exactly as many # as the opener had.
        m = RAW_START.match(src, i)
        if m:
            close = '"' + m.group(1)
            end = src.find(close, m.end())
            end = n if end == -1 else end + len(close)
            out.append(src[i:end])
            i = end
            continue

        # Ordinary or byte string: backslash escapes any following character.
        if ch == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
            continue

        # `'` opens either a character literal or a lifetime. `'\...'` is always
        # a literal; `'x'` is one when the character after next closes it;
        # anything else (`'a`, `'static`) is a lifetime and needs no skipping.
        if ch == "'":
            if src[i + 1 : i + 2] == "\\":
                j = i + 2
                while j < n and src[j] != "'":
                    j += 2 if src[j] == "\\" else 1
                j = min(j + 1, n)
                out.append(src[i:j])
                i = j
                continue
            if src[i + 2 : i + 3] == "'":
                out.append(src[i : i + 3])
                i += 3
                continue
            out.append(ch)
            i += 1
            continue

        # Identifiers are consumed whole so that a `r` inside one (`over`,
        # `char`) is never mistaken for a raw-string prefix.
        m = IDENT.match(src, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue

        if src.startswith("//", i):
            is_doc = src[i + 2 : i + 3] in ("/", "!") and not src.startswith("////", i)
            if keep_doc and is_doc:
                j = src.find("\n", i)
                j = n if j == -1 else j
                out.append(src[i:j])
                i = j
                continue
            j = src.find("\n", i)
            i = n if j == -1 else j  # leave the newline for the blank-line pass
            continue

        if src.startswith("/*", i):
            is_doc = src[i + 2 : i + 3] in ("*", "!") and not src.startswith("/**/", i)
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            if keep_doc and is_doc:
                out.append(src[i:j])
            i = j
            continue

        out.append(ch)
        i += 1

    return drop_blanked_lines("".join(out), src)


def drop_blanked_lines(stripped: str, original: str) -> str:
    """Trim trailing space, and drop lines a removed comment emptied."""
    before = original.split("\n")
    kept = []
    for k, line in enumerate(stripped.split("\n")):
        trimmed = line.rstrip()
        if not trimmed and k < len(before) and before[k].strip():
            continue  # the line held only a comment
        kept.append(trimmed)
    # Removing a comment that sat above a blank separator leaves that blank behind: at the
    # top of a file it becomes a leading blank line, and mid-file it doubles an existing gap.
    while kept and not kept[0]:
        kept.pop(0)
    collapsed = []
    for line in kept:
        if not line and collapsed and not collapsed[-1]:
            continue
        collapsed.append(line)
    text = "\n".join(collapsed)
    return text if text.endswith("\n") or not text else text + "\n"


def rust_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for d, dirs, fs in os.walk(p):
            dirs[:] = [x for x in dirs if x not in ("target", ".git")]
            for f in sorted(fs):
                if f.endswith(".rs"):
                    yield os.path.join(d, f)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--write", action="store_true", help="rewrite files in place")
    ap.add_argument("--keep-doc", action="store_true", help="keep /// //! /** */ /*! */")
    a = ap.parse_args()

    files = changed = removed = 0
    for path in rust_files(a.paths or ["."]):
        files += 1
        src = open(path, encoding="utf-8").read()
        new = strip(src, a.keep_doc)
        if new == src:
            continue
        changed += 1
        gone = len(src.split("\n")) - len(new.split("\n"))
        removed += gone
        print(f"{path}: -{gone} lines")
        if a.write:
            open(path, "w", encoding="utf-8").write(new)

    verb = "rewrote" if a.write else "would rewrite"
    print(f"\n{files} files scanned, {verb} {changed}, -{removed} lines")
    if not a.write and changed:
        print("no files written; pass --write to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
