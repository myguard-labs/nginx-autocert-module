# fixture: workflow-level-env-cross-file-collision

The neighbour of `workflow-level-env-shared-two-jobs`, one file over.

Registering a workflow-level `env:` band once per FILE fixes the self-collision
between jobs sharing one declaration, but only while THIS file wins the
registration. The suppression that made it work asked "is the claimant recorded
in `bands` me?" -- and on a cross-FILE collision the claimant is the *other*
file, so the answer is no for every job, and each one re-reports the same single
collision: one real conflict, reported once by the file-level registration and
once more by every job in the losing file. Which file loses decides the count,
so the duplication only shows when the loser is the file with jobs to spare --
here b.yml, with two, giving three reports for one conflict.

Here `a.yml` (one job) and `b.yml` (two jobs) both claim
`TEST_BASE_PORT: '19900'` at workflow level. That IS a genuine collision: the
bands must be disjoint across all workflows, so `ports` must stay red. What must
not happen is reporting it three times.

Exit status and message text are the same in both directions -- the broken shape
emits the correct finding, just twice more here -- so the control that discriminates
is the occurrence COUNT, plus an absence assertion on the `b.yml:<job>` prefix
the per-job repeats carried.
