# fixture: action-level-env-declared

Per-step checking on a composite action's `runs.steps` cannot see a
declaration made in the action's own top-level `env:` block (or, before that,
one made in `runs.env:`), because the old per-step `_body(step)` dump never
included it. The binding step's own body has no `TEST_BASE_PORT:` line, so it
read as "binds a port without declaring TEST_BASE_PORT" -- a false positive on
the idiomatic declare-then-bind split, where the declaration is deliberately
lifted out of each step and shared by all of them.

`ports` must report CLEAN here: the action-level `env:` declares the band, one
step verifies it free, and another binds it via the runtime driver with
`--port "$TEST_BASE_PORT"`.

Action: `.github/actions/build/action.yml`.
