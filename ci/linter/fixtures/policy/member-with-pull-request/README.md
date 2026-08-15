# fixture: member-with-pull-request

A `workflow_call` member that also carries `pull_request:`. That invokes the
same PR both through `ci.yml` and directly, so `cadence` must go red. Its
neighbours prove that direct default-branch `push:` and `schedule:` remain
intentional, permitted entry points.

Workflow: `.github/workflows/build-test.yml`.
