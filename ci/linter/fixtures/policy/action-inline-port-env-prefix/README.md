# action-inline-port-env-prefix

Action `a` claims a band with `env AC_TEST_PORT=18500 cmd`; action `b` claims
the same band with a plain assignment. `env VAR=val cmd` is the idiomatic way
to set a port for exactly one invocation, so it must enter the uniqueness set.

A statement-boundary match that permits only `export` as a prefix word misses
it, the two actions look disjoint, and a real collision between two jobs on a
shared runner passes green -- surfacing later as a flaky bind failure.

Expected: exit 1, the cross-action collision reported.
