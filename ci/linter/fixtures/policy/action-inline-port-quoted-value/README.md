# action-inline-port-quoted-value

Action `a` claims 18501 with a quoted value and also sets `AC_TEST_PORTABLE`,
a different variable whose name merely starts with the token. Action `b`
claims 18501 unquoted.

Quoting a value is idiomatic and claims the same band, so the two actions
collide. `AC_TEST_PORTABLE` must not be counted: treating the name as a prefix
rather than an exact match with an optional numeric suffix would register
18500 as a phantom band.

Expected: exit 1, the collision on 18501 reported and 18500 absent.
