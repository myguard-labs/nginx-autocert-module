#!/usr/bin/env bash
# ci/linter/lint-python.sh -- ruff lint + format check over every tracked *.py.
#
# There is one Python file in this repo, and it is not a peripheral one:
# ci/linter/workflow_policy.py implements the rule for FIVE of the eleven
# checkers (ports, secrets, docs, cadence, runners) -- lint-ci-ports.sh and its
# four siblings are `exec python3 .../workflow_policy.py <subcommand>` and
# nothing else. Every policy verdict this linter tree produces about the
# workflows comes out of that file, and until this checker existed, the linter
# tree linted everything except the code doing the linting.
#
# ruff, not flake8/pylint: install-linters.sh already provisions
# `ruff==0.16.1` via pipx, and has since before this checker existed -- the
# tool was pinned for a gate that was never wired up. Nothing else needed to be
# added to the toolchain to close this gap.
#
# PINNED on purpose (0.16.1, in install-linters.sh): an unpinned ruff changes
# its findings under you and local green stops predicting remote green. Same
# reasoning as the semgrep and actionlint pins.
#
# --select is EXPLICIT, and that is the whole difference between this being a
# gate and being decoration. `ruff check` with no configuration enables only a
# small default subset -- it does NOT include F401 (unused import) or E402
# (import not at top of file). Verified while writing this checker: appending a
# stray `import os` to workflow_policy.py left a bare `ruff check` reporting
# "All checks passed!", including under --isolated, while
# `--select F401,E402` on the same file exited 1.
#
# Do not read the 415-entry `linter.rules.enabled` list in
# `ruff check --show-settings` as the selected set -- that is the rules ruff
# KNOWS, not the rules it RUNS. Reading it as coverage is exactly how a linter
# gets adopted, reported clean, and never fails.
#
#   E,W  pycodestyle       F   pyflakes (unused imports/names, real bugs)
#   B    bugbear           SIM flake8-simplify
#   I    import sorting    UP  pyupgrade
#
# Two passes, both gating:
#   ruff check     -- the rule set above. This tree passes it clean today, so a
#                     finding here is a real regression rather than a backlog
#                     of pre-existing noise to triage.
#   ruff format    -- --check --diff, so a reformat is reported as a diff
#                     rather than silently applied. A checker must never
#                     rewrite the tree it is inspecting; that is the fixer
#                     hooks' job in .pre-commit-config.yaml, not this one's.
#
# Usage: ci/linter/lint-python.sh [files...]   Env: LINT_MODE=staged|all
# Extend: add rule families to the --select below. A [tool.ruff] table in a
# pyproject.toml at the repo root would also be honoured, but the selection is
# kept HERE on purpose -- a reader of this script can see which rules gate
# without opening a second file, and a config that silently narrows the set is
# the failure mode documented above.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '\.py$' "$@")
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-python: no Python files to check"; exit 0; }

echo "lint-python: ${#FILES[@]} file(s)"
rc=0

need ruff "pipx install ruff==0.16.1  (see install-linters.sh)"

say "ruff check (E,W,F,B,SIM,I,UP)"
ruff check --no-cache --select E,W,F,B,SIM,I,UP "${FILES[@]}" || rc=1

say "ruff format (--check)"
ruff format --no-cache --check --diff "${FILES[@]}" || rc=1

exit "$rc"
