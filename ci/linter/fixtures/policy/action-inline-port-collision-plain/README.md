# fixture: action-inline-port-collision-plain

Two steps in `.github/actions/dup/action.yml` inline-claim the same
`AC_TEST_PORT=18500`, each inside a plain multi-line `run:` block with no
backslash continuation and no `${{ }}` expression. `yaml.safe_dump` re-emits
that shape as a single-quoted (folded) scalar with REAL newlines, not the
escaped double-quoted scalar with literal `\n` text that `INLINE_PORT_RE`'s
`(?:^|\\n)` alternation is built to see.

`ports` must go red naming the collision. A regex anchored only to string-start
or a literal backslash-n reports "no runtime-bearing jobs" here and lets a real
same-port collision through.

Both steps live in the same action file, so the finding also exercises the
same-node ("claims AC_TEST_PORT ... twice") message rather than the
cross-node collision wording.
