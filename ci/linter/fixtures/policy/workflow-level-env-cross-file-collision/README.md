# fixture: workflow-level-env-cross-file-collision

The neighbour of `workflow-level-env-shared-two-jobs`, one file over.

`a.yml` (one job) and `b.yml` (two jobs) both claim `TEST_BASE_PORT: '19900'`
at workflow level. That IS a genuine collision -- the bands must be disjoint
across all workflows -- so `ports` must stay red, and it is red in both the
fixed and the broken shape.

What the fixture pins is therefore not the verdict but the number of times it
is reported. Registering a workflow-level band once per FILE fixes the
self-collision between jobs sharing one declaration, but a suppression keyed on
"is the claimant recorded in `bands` me?" never fires on a cross-FILE
collision, because the claimant is the other file. Every job in the losing file
then re-reports the one conflict. `b.yml` is the loser here and has the jobs to
make that visible.

The assertions are in `ci/linter/selftest.sh`; the expected counts and why they
depend on which file loses live at that call site, not here.
