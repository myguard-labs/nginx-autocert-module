#!/usr/bin/env bash
# ci/linter/lint-yaml.sh -- yamllint over every *.yml/*.yaml, plus actionlint
# over .github/workflows/*.
#
# Workflows are code that fails silently: a bad `if:` expression, an unknown
# context or a shell error inside a `run:` block does not stop the run, it
# makes the job pass while checking nothing. actionlint is the only checker
# here that reads them as GitHub Actions rather than as YAML.
#
#   -ignore 'label ".+" is unknown'
#       actionlint 1.7.7 carries a FIXED list of runner images and flags newer
#       ones (ubuntu-26.04, ubuntu-26.04-arm) as unknown. Every such report is
#       about the linter's age, not the workflow. Drop the ignore once
#       actionlint is new enough to know the labels this repo targets.
#   SHELLCHECK_OPTS=-Swarning
#       actionlint's embedded shellcheck otherwise reports at info while
#       lint-sh.sh gates at warning -- same finding, two verdicts.
#
# No --strict on yamllint, on purpose: warnings (long inline `run:` lines) stay
# visible without failing the gate, errors still block. The rule set lives in
# .yamllint at the repo root so editors and this script agree.
#
# actionlint and zizmor are not alternatives: actionlint reads a workflow as
# SYNTAX (bad if:, unknown context, shell error in run:), zizmor reads it as an
# ATTACK SURFACE (template injection, dangerous triggers, leaked credentials,
# unpinned actions, over-broad permissions). This repo targets self-hosted
# runners, where a workflow-level mistake is arbitrary code execution on the
# build host -- so the security pass is not optional here.
#
# --persona=pedantic, not the default: the default already passes on this tree,
# so gating on it would never go red. Pedantic is what caught the matrix
# interpolations in ci-deep.yml and the undocumented CodeQL permissions. Findings
# that are genuinely inapplicable get a `# zizmor: ignore[rule]` at the line,
# with the reason -- never a blanket rule disable in zizmor.yml.
#
# DO NOT "fix" the self-repository findings by taking zizmor's offered autofix.
# zizmor wants `uses: $/.github/actions/setup` instead of `./...`. That IS real
# GitHub Actions syntax, but actionlint 1.7.7 REJECTS it (actionlint#711), and
# both tools run in this script under `|| rc=1` -- so applying the autofix just
# moves the red from zizmor to actionlint. The findings are suppressed per line
# instead. Revisit only once actionlint accepts `$/`; then drop the
# `# zizmor: ignore[self-repository]` comments and re-run this script.
#
# --offline: no API calls from a commit hook. The online audits need a token and
# only add repo-settings context, which belongs in a periodic review, not here.
#
# Usage: ci/linter/lint-yaml.sh [files...]   Env: LINT_MODE=staged|all
# Extend: yamllint rules live in .yamllint at the repo root.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '\.ya?ml$' "$@")
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-yaml: no YAML files to check"; exit 0; }

echo "lint-yaml: ${#FILES[@]} file(s)"
rc=0

need yamllint "apt-get install yamllint"
say "yamllint"
# Gate on the SEVERITY of what yamllint reported, not on its exit status.
#
# The exit status is not a portable signal here. yamllint auto-detects a
# GitHub Actions runner and switches to `-f github`, and the exit code it
# pairs with a warnings-only run has differed between the local Debian
# package (1.37.1) and the pipx build the runner resolves -- yamllint is
# unpinned, so that build moves on its own. `|| rc=1` therefore turned
# repo-wide WARNINGS into a red gate on CI while passing locally, on files
# the branch never touched.
#
# `-f parsable` fixes the output shape on every version and runner, so
# counting `[error]` lines is a stable gate. Warnings stay visible and do not
# fail, which is the "No --strict on yamllint, on purpose" contract at the
# top of this script; error-level findings still block.
#
# The output is captured rather than streamed so it can be both counted and
# printed; yamllint's own exit status is deliberately ignored.
yaml_out="$(yamllint -f parsable "${FILES[@]}" 2>&1 || true)"
[ -n "$yaml_out" ] && printf '%s\n' "$yaml_out"
if printf '%s\n' "$yaml_out" | grep -q '\[error\]'; then
    rc=1
fi

mapfile -t WF < <(printf '%s\n' "${FILES[@]}" | grep -E '^\.github/workflows/' || true)
if [ "${#WF[@]}" -gt 0 ]; then
    need actionlint "go install github.com/rhysd/actionlint/cmd/actionlint@latest  (see install-linters.sh)"
    say "actionlint (${#WF[@]} workflow(s))"
    SHELLCHECK_OPTS=-Swarning \
        actionlint -ignore 'label ".+" is unknown' "${WF[@]}" || rc=1

    need zizmor "pipx install zizmor"
    say "zizmor (workflow security, pedantic)"
    zizmor --offline --persona=pedantic --no-progress "${WF[@]}" || rc=1
fi

exit "$rc"
