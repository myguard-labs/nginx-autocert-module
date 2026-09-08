# action-inline-port-keyword-lead

Action `a` claims a band inside `if true; then AC_TEST_PORT=18500 cmd; fi`;
action `b` claims the same band with a plain assignment. A shell statement also
begins after `then`, `do` and `else`, so an opener set built only from
punctuation misses a conditional or loop body and reports the two actions as
disjoint.

Expected: exit 1, the cross-action collision reported.
