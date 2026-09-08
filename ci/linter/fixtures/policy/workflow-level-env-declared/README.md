# fixture: workflow-level-env-declared

Per-job checking roots the body dump at the job node (`_body(node)`), which
never contains a declaration made in the WORKFLOW's own top-level `env:`
block -- same false-positive shape `action-level-env-declared` already covers
for a composite action, one level up: `jobs()` hands out job nodes, and a
workflow-level `env:` sits on `doc`, above every one of them.

The single job's own body has no `TEST_BASE_PORT:` line, so it used to read
as "binds a port without declaring TEST_BASE_PORT" -- a false positive on the
idiomatic case where the declaration is lifted to the workflow and shared by
every job.

`ports` must report CLEAN here: the workflow-level `env:` declares the band
and the one job binds it via the runtime driver with
`--port "$TEST_BASE_PORT"`.
