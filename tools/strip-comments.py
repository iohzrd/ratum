#!/usr/bin/env python3
"""Remove every comment from Rust source files.

The file is scanned as Rust tokens, not with pattern matching, so text that only
resembles a comment is kept: `"http://host"` keeps its `//`, the raw string
`r#"/* text */"#` keeps its body, and `&'a str` is read as a lifetime rather than
an unterminated character literal. Nested block comments are counted to their
matching close, as rustc counts them.

Removed: line comments (`//`), block comments (`/* */`), and the doc comments
`///`, `//!`, `/** */` and `/*! */` unless --keep-doc is given. `#[doc = "..."]`
is an attribute, not a comment, and is never touched.

Line cleanup, applied only to lines a removed comment touched:
  - trailing spaces and tabs left by a comment that followed code are trimmed;
  - a line that held only a comment is deleted;
  - a blank line that a deletion left doubled, or left at the top of the file,
    is deleted with it.
A line that ends inside a multi-line string literal is never trimmed or deleted,
so literal contents are byte-identical before and after.

Without --write the tool reports the files it would change and writes nothing.

usage:
  tools/strip-comments.py [PATH ...]             report only
  tools/strip-comments.py --write [PATH ...]     rewrite in place
  tools/strip-comments.py --keep-doc [PATH ...]  keep /// //! /** */ /*! */
  tools/strip-comments.py - < in.rs > out.rs     filter stdin to stdout
PATH defaults to the current directory. A directory is searched for *.rs files;
target/ and .git/ are skipped.
"""

import argparse
import os
import re
import sys

RAW_STRING_START = re.compile(r'(?:b|c)?r(#*)"')
IDENT = re.compile(r"[^\W\d]\w*")


class _Lines:
    """Output accumulator: one entry per output line with the flags the cleanup pass reads.

    `removed` is set on a line from which a comment was removed. `protected` is set on a
    line whose terminating newline lies inside a string literal; such a line is copied
    through the cleanup pass unchanged.
    """

    def __init__(self):
        self.lines = []
        self.buf = []
        self.removed = False
        self.protected = False

    def emit(self, text: str, in_literal: bool = False):
        parts = text.split("\n")
        for k, part in enumerate(parts):
            self.buf.append(part)
            if k < len(parts) - 1:
                self._end_line(protected=in_literal)

    def _end_line(self, protected: bool):
        self.lines.append(("".join(self.buf), self.removed, self.protected or protected))
        self.buf = []
        self.removed = False
        self.protected = False

    def last_char(self):
        for part in reversed(self.buf):
            if part:
                return part[-1]
        return ""

    def finish(self):
        self.lines.append(("".join(self.buf), self.removed, self.protected))
        return self.lines


def strip(src: str, keep_doc: bool = False) -> str:
    """Return `src` with its comments removed."""
    out = _Lines()
    i, n = 0, len(src)
    while i < n:
        ch = src[i]

        # Raw string: r"..", br#".."#, cr##".."##. No escapes inside; the close is the
        # quote followed by as many `#` as the opener had.
        m = RAW_STRING_START.match(src, i)
        if m:
            close = '"' + m.group(1)
            end = src.find(close, m.end())
            end = n if end == -1 else end + len(close)
            out.emit(src[i:end], in_literal=True)
            i = end
            continue

        # Ordinary, byte or C string: a backslash escapes the following character.
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
            j = min(j, n)
            out.emit(src[i:j], in_literal=True)
            i = j
            continue

        # `'` opens a character literal or a lifetime. `'\...'` is a literal: the escaped
        # character is skipped and the literal runs to the next quote. `'x'` is a literal
        # when the character after next is the closing quote. Anything else (`'a`,
        # `'static`) is a lifetime and needs no skipping.
        if ch == "'":
            if src[i + 1 : i + 2] == "\\":
                j = src.find("'", i + 3)
                j = n if j == -1 else j + 1
                out.emit(src[i:j])
                i = j
                continue
            if src[i + 2 : i + 3] == "'":
                out.emit(src[i : i + 3])
                i += 3
                continue
            out.emit(ch)
            i += 1
            continue

        # An identifier is consumed whole so that an `r` inside one (`over`, `char`) is
        # never read as a raw-string prefix.
        m = IDENT.match(src, i)
        if m:
            out.emit(m.group(0))
            i = m.end()
            continue

        if src.startswith("//", i):
            is_doc = src[i + 2 : i + 3] in ("/", "!") and not src.startswith("////", i)
            j = src.find("\n", i)
            j = n if j == -1 else j
            if j > i and src[j - 1] == "\r":
                j -= 1
            if keep_doc and is_doc:
                out.emit(src[i:j])
            else:
                out.removed = True
            i = j
            continue

        if src.startswith("/*", i):
            # As rustc classifies it: `/*!` is a doc comment, and `/**` is one unless the
            # next character is `*` or `/` (`/**/`, `/***/` are plain block comments).
            third, fourth = src[i + 2 : i + 3], src[i + 3 : i + 4]
            is_doc = third == "!" or (third == "*" and fourth not in ("*", "/"))
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
                out.emit(src[i:j])
            else:
                # A comment separates tokens, so a single space stands in for it when
                # non-space characters are on both sides: `a/**/b` becomes `a b`.
                prev = out.last_char()
                nxt = src[j : j + 1]
                if prev and not prev.isspace() and nxt and not nxt.isspace():
                    out.emit(" ")
                out.removed = True
            i = j
            continue

        out.emit(ch)
        i += 1

    return _cleanup(out.finish())


def _cleanup(lines) -> str:
    """Apply the line cleanup described in the module docstring."""
    kept = []
    # Set after a line was deleted and cleared by the next line that is kept; while set,
    # a blank line that would double the previous blank (or open the file) is deleted.
    deleted = False
    for text, removed, protected in lines:
        if protected:
            kept.append(text)
            deleted = False
            continue
        if removed:
            eol = "\r" if text.endswith("\r") else ""
            text = text[: len(text) - len(eol)].rstrip(" \t") + eol
            if not text.strip():
                deleted = True
                continue
        if deleted and not text.strip() and (not kept or not kept[-1].strip()):
            continue
        kept.append(text)
        deleted = False
    return "\n".join(kept)


def rust_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for d, dirs, fs in os.walk(p):
            dirs[:] = sorted(x for x in dirs if x not in ("target", ".git"))
            for f in sorted(fs):
                if f.endswith(".rs"):
                    yield os.path.join(d, f)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="*", default=["."], help="files or directories; - for stdin")
    ap.add_argument("--write", action="store_true", help="rewrite files in place")
    ap.add_argument("--keep-doc", action="store_true", help="keep /// //! /** */ /*! */")
    a = ap.parse_args()

    if a.paths == ["-"]:
        sys.stdout.write(strip(sys.stdin.read(), a.keep_doc))
        return 0

    files = changed = removed = 0
    for path in rust_files(a.paths):
        files += 1
        with open(path, encoding="utf-8", newline="") as f:
            src = f.read()
        new = strip(src, a.keep_doc)
        if new == src:
            continue
        changed += 1
        gone = src.count("\n") - new.count("\n")
        removed += gone
        print(f"{path}: -{gone} lines")
        if a.write:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(new)

    verb = "rewrote" if a.write else "would rewrite"
    plural = "" if files == 1 else "s"
    print(f"{files} file{plural} scanned, {verb} {changed}, -{removed} lines")
    if not a.write and changed:
        print("no files written; pass --write to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main())
