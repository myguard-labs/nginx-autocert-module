#!/usr/bin/env python3
"""Reject CA-controlled fields in non-debug nginx log calls.

Usage: ca_log_safety.py FILE [FILE ...]

The lexer understands C strings, character literals, and both comment forms.
Calls are walked by balanced parentheses, so formatting, comments, nested calls,
and multiple statements on one line cannot alter the result.
"""

from __future__ import annotations

import dataclasses
import pathlib
import sys

# Auditable inventory of opaque CA-derived ngx_str_t members.  Keep this in
# sync with ngx_autocert_{acme,account,order}.h.  request.url is supplied from
# the CA after the configured directory fetch; body_out and cert_chain are
# opaque response bytes.  Account/order URL members and kid/nonce come from
# directory JSON, resource JSON, Location, or Replay-Nonce response headers.
CONTROLLED_FIELDS = frozenset(
    {
        "url",
        "body_out",
        "kid",
        "nonce",
        "new_nonce_url",
        "new_account_url",
        "post_url",
        "new_order_url",
        "order_url",
        "finalize_url",
        "authz_url",
        "challenge_url",
        "cert_url",
        "cert_chain",
    }
)
# Intentionally excluded CA-derived members are safe by construction:
# request.host/request.uri pass ngx_autocert_acme_url_part_safe(); response
# header names/values cannot contain CR/LF because the HTTP parser splits them
# at CRLF; order.token passes ngx_autocert_order_token_safe(), and keyauth plus
# dns_txt_value are then built entirely from restricted base64url characters.
SAFE_WRAPPERS = frozenset(
    {"ngx_autocert_acme_log_safe", "ngx_autocert_account_log_safe"}
)


@dataclasses.dataclass(frozen=True)
class Token:
    text: str
    line: int


def splice_lines(source: str) -> tuple[str, list[int]]:
    """Apply C translation-phase line splicing and retain physical lines."""
    output: list[str] = []
    lines: list[int] = []
    physical_line = 1
    i = 0
    while i < len(source):
        if source.startswith("\\\n", i):
            physical_line += 1
            i += 2
            continue
        output.append(source[i])
        lines.append(physical_line)
        physical_line += source[i] == "\n"
        i += 1
    return "".join(output), lines


def tokenize(source: str, filename: str) -> list[Token]:
    source, physical_lines = splice_lines(source)
    tokens: list[Token] = []
    i = 0
    size = len(source)
    while i < size:
        char = source[i]
        line = physical_lines[i]
        if char.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = size if end < 0 else end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                raise ValueError(f"{filename}:{line}: unterminated C comment")
            i = end + 2
            continue
        if char in {'"', "'"}:
            quote = char
            start_line = line
            i += 1
            while i < size and source[i] != quote:
                if source[i] == "\\" and i + 1 < size:
                    i += 2
                else:
                    i += 1
            if i >= size:
                raise ValueError(f"{filename}:{start_line}: unterminated C literal")
            i += 1
            tokens.append(Token("<literal>", start_line))
            continue
        if char.isalpha() or char == "_":
            end = i + 1
            while end < size and (source[end].isalnum() or source[end] == "_"):
                end += 1
            tokens.append(Token(source[i:end], line))
            i = end
            continue
        if source.startswith("->", i):
            tokens.append(Token("->", line))
            i += 2
            continue
        tokens.append(Token(char, line))
        i += 1
    return tokens


def closing_parens(tokens: list[Token]) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, token in enumerate(tokens):
        if token.text == "(":
            stack.append(index)
        elif token.text == ")" and stack:
            pairs[stack.pop()] = index
    return pairs


def macro_definition_lines(source: str) -> set[int]:
    """Return physical lines belonging to a continued #define directive."""
    result: set[int] = set()
    continuing = False
    for line_number, line in enumerate(source.splitlines(), 1):
        directive = line.lstrip()
        words = (
            directive[1:].lstrip().split(maxsplit=1)
            if directive.startswith("#")
            else []
        )
        if continuing or (words and words[0] == "define"):
            result.add(line_number)
            continuing = line.rstrip().endswith("\\")
        else:
            continuing = False
    return result


def statement_end(tokens: list[Token], opening: int) -> int | None:
    """Find a call's semicolon without stopping in nested C expressions."""
    brace_depth = 0
    for cursor in range(opening + 1, len(tokens)):
        if tokens[cursor].text == "{":
            brace_depth += 1
        elif tokens[cursor].text == "}":
            brace_depth -= 1
        elif tokens[cursor].text == ";" and brace_depth == 0:
            return cursor
    return None


def conditional_paths(source: str) -> dict[int, tuple[int, ...]]:
    """Map physical lines to their complete preprocessor branch path."""
    result: dict[int, tuple[int, ...]] = {}
    path: list[int] = []
    for line_number, line in enumerate(source.splitlines(), 1):
        directive = line.lstrip()
        result[line_number] = tuple(path)
        if not directive.startswith("#"):
            continue
        words = directive[1:].lstrip().split(maxsplit=1)
        keyword = words[0] if words else ""
        if keyword in {"if", "ifdef", "ifndef"}:
            path.append(0)
        elif keyword in {"elif", "else"} and path:
            path[-1] += 1
        elif keyword == "endif" and path:
            path.pop()
    return result


def findings(path: pathlib.Path) -> list[tuple[int, str]]:
    source = path.read_text(encoding="utf-8")
    tokens = tokenize(source, str(path))
    pairs = closing_parens(tokens)
    macro_lines = macro_definition_lines(source)
    paths = conditional_paths(source)
    wrappers = [
        (index + 1, pairs[index + 1])
        for index, token in enumerate(tokens[:-1])
        if token.text in SAFE_WRAPPERS
        and tokens[index + 1].text == "("
        and index + 1 in pairs
        # A wrapper opened inside one conditional branch and closed outside it
        # is ambiguous in raw tokens.  A wrapper surrounding the whole
        # conditional is safe: every selected argument still passes through it.
        and paths.get(tokens[index].line, ())
        == paths.get(tokens[pairs[index + 1]].line, ())
    ]
    found: list[tuple[int, str]] = []
    for index, token in enumerate(tokens[:-1]):
        if not token.text.startswith("ngx_log_") or tokens[index + 1].text != "(":
            continue
        if token.text.startswith("ngx_log_debug"):
            continue
        # Function-like macro bodies need no trailing semicolon, so their own
        # balanced call is the boundary.  Ordinary source uses the first real
        # semicolon: unlike raw parenthesis pairing, that sees both alternatives
        # of a valid #if/#else call whose inactive branch unbalances raw tokens.
        end = (
            pairs.get(index + 1)
            if token.line in macro_lines
            else statement_end(tokens, index + 1)
        )
        if end is None:
            raise ValueError(f"{path}:{token.line}: unterminated {token.text} call")
        for field_index in range(index + 2, end - 1):
            field_path = paths.get(tokens[field_index].line, ())
            wrapped = any(
                index + 1 < start <= field_index < stop <= end
                and field_path[: len(paths.get(tokens[start - 1].line, ()))]
                == paths.get(tokens[start - 1].line, ())
                for start, stop in wrappers
            )
            if (
                tokens[field_index].text == "->"
                and tokens[field_index + 1].text in CONTROLLED_FIELDS
                and not (
                    field_index + 3 < end
                    and tokens[field_index + 2].text == "."
                    and tokens[field_index + 3].text == "len"
                )
                and not wrapped
            ):
                found.append((token.line, tokens[field_index + 1].text))
    return found


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: ca_log_safety.py FILE [FILE ...]", file=sys.stderr)
        return 2
    try:
        all_findings = [
            (path, line, field)
            for name in argv
            for path in [pathlib.Path(name)]
            for line, field in findings(path)
        ]
    except (OSError, UnicodeError, ValueError) as error:
        print(f"lint-ca-log-safety: cannot inspect input: {error}", file=sys.stderr)
        return 2
    for path, line, field in all_findings:
        print(
            f"{path}:{line}: unwrapped CA-controlled field '{field}' "
            "in non-debug ngx_log_* call"
        )
    return 1 if all_findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
