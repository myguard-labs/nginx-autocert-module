# fixture: workflow-level-env-shared-two-jobs

The trap in the workflow-level-env fix: registering the shared declaration
must happen ONCE per file, not once per job. Appending the workflow `env:`
text to every job's body so each job's own `declared` regex can see it is
correct; re-registering that same port into `bands` for every job that then
matches it is not -- with N jobs sharing one workflow-level `TEST_BASE_PORT`,
a naive per-job registration collides the jobs with EACH OTHER, which is
false: they own the same file-level band on purpose, not two conflicting
claims.

Two jobs here both bind the runtime driver using the single workflow-level
`TEST_BASE_PORT: '19900'`. `ports` must report CLEAN -- no self-collision
between `build` and `test` over the one shared declaration.
