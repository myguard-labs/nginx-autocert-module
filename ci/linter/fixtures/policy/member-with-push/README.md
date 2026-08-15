# fixture: member-with-push

A `workflow_call` member that also carries its own `push: branches: [main]`.
`push:` is intentionally allowed: the direct default-branch run proves the
merged tree, while the `workflow_call` run proves the PR head. The policy
decision recorded on 2026-08-15 retains this coverage for build-test, CodeQL,
and security scanners. `cadence` must stay green here.

Workflow: `.github/workflows/build-test.yml`.
