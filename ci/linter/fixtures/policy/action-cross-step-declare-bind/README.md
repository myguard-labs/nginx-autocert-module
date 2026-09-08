# fixture: action-cross-step-declare-bind

Per-step checking (`_body(step)`) treats each step's YAML dump as an isolated
universe. When one step declares `TEST_BASE_PORT` under its own `env:` and a
*sibling* step is the one that actually runs the runtime driver with
`--port "$TEST_BASE_PORT"`, the binding step's own body never contains a
`TEST_BASE_PORT:` line -- another false-positive shape of the same
declare-then-bind split as `action-level-env-declared`, one level down (step
env rather than action env).

`ports` must report CLEAN here: the union of the action's steps carries both
the declaration and the passthrough bind.

Action: `.github/actions/build/action.yml`.
