# fixture: schedule-only-runner-labels

Encodes the bypass: **a runner label typo in a workflow that no pull request can
reach was checked by nothing at all.**

`check_runners` used to `continue` past any workflow whose triggers did not
include `pull_request` or `workflow_call`, because the fork-trust question only
applies to a job a fork can cause to run. That skipped the exact-string
membership test with it, and that membership test is the only thing in this
toolchain that reads the pool labels.

actionlint does not cover the gap. It validates runner labels for a LITERAL
`runs-on` only; every self-hosted selector in this repo is a `fromJSON(...)`
ternary, which it walks past without a word — so `.github/actionlint.yaml`'s
declared-label list is never consulted for them. A quiet linter and a clean
linter print the same thing.

Measured in the real tree, 2026-08-02: `builder02` -> `buidler02` in
`build-test.yml` (`workflow_call`, PR-reachable) was reported; the same edit in
`bump.yml` and `ci-deep.yml` (`schedule` + `workflow_dispatch`) was silent, on
both this check and actionlint. Six selectors had no label checking anywhere.

The failure mode is why it is worth a gate: an unknown label is not a lint error
and not a dispatch error. It is a queued job that never picks up a runner, on a
weekly schedule nobody is watching.

`nightly.yml` here is that shape — schedule-only, one mistyped pool label.
Expected: `runners` exit 1.

The GREEN half of this control is the sibling fixture
`schedule-only-runner-labels-ok` — the same file with the label spelled right,
which must stay silent. Without it, a red here could be "non-PR-reachable
workflows are now always flagged" rather than "the typo is caught".
