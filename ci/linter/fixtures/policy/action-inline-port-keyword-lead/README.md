# action-inline-port-keyword-lead

Action `a` claims a band from inside a conditional body
(`if true; then AC_TEST_PORT=18500 cmd; fi`); action `b` claims a different
band with a plain assignment.

The check walks only the assignment prefix at the head of each line, so an
assignment introduced by a shell keyword is NOT counted. That is a deliberate
limitation: recognising it correctly needs real shell tokenization, and the
alternative -- widening the pattern until keywords match -- is what admits
comments and diagnostic strings as phantom claimants.

This control pins the limitation so it stays a known, reviewed gap rather than
drifting into a silent one.

Expected: exit 0. A band claimed this way does not enter the uniqueness set.
