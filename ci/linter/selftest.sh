#!/usr/bin/env bash
# ci/linter/selftest.sh -- negative controls for the lint gate itself.
#
# The gate is the thing that decides whether everything else is allowed to
# land, so "the gate ran and said clean" has to be distinguishable from "the
# gate ran nothing and said clean". That distinction is not observable from a
# green lint job: a selector typo used to make run-all.sh print
# "== all linters clean ==" and exit 0 having executed zero checkers.
#
# Every case here asserts the FAILING direction -- a check that only ever
# asserts the passing direction cannot detect its own disarming.
#
# Usage:  ci/linter/selftest.sh
# Exit:   0 all controls held, 1 one or more did not.
#
# Runs in about a second: no case invokes a real checker (LINT_ONLY values are
# either bogus or rejected before dispatch), so no linter needs to be installed.
#
# Extend: add a case() line. Keep each case asserting a specific exit status,
# and prefer a case where the OLD, broken behaviour would have passed.

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2

rc=0

# case <expected-exit> <description> -- command...
case_() {
    local want="$1" desc="$2"; shift 2
    local out got
    out="$("$@" 2>&1)"; got=$?
    if [ "$got" -eq "$want" ]; then
        echo "ok   $desc (exit $got)"
    else
        echo "FAIL $desc: expected exit $want, got $got" >&2
        echo "$out" | sed 's/^/       | /' >&2
        rc=1
    fi
}

# The regression itself: an unmatched selector must be "could not run" (2),
# not "clean" (0).
case_ 2 "unknown LINT_ONLY exits 2" \
    env LINT_ONLY=nosuchchecker ci/linter/run-all.sh

# ...including when only SOME of the listed names are bogus in a way that
# leaves nothing selected.
case_ 2 "LINT_ONLY of only-bogus names exits 2" \
    env LINT_ONLY="c-lang shellscript" ci/linter/run-all.sh

# The error names the offending value and the known checkers, or nobody can
# act on it.
# Captured first, not piped into grep: `set -o pipefail` would otherwise hand
# the pipeline run-all.sh's exit 2 and the assertion would read as failed no
# matter what the message said.
msg="$(env LINT_ONLY=nosuchchecker ci/linter/run-all.sh 2>&1)"
if printf '%s\n' "$msg" | grep -q 'matched no checker; known: .*sh'; then
    echo "ok   unmatched-selector message names value and known checkers"
else
    echo "FAIL unmatched-selector message is not actionable" >&2
    rc=1
fi

# Positive control: the selector still selects. --list is used rather than a
# real run so this stays independent of which linters are installed.
case_ 0 "--list works" ci/linter/run-all.sh --list

# ----------------------------------------------------------------------------
# workflow_policy.py -- the red path of each policy check.
#
# Every fixture below encodes a bypass that VALID YAML used to walk straight
# through while the checks parsed workflows by regex. Each was verified in both
# directions when it was written: red on the current parser, green on the
# regex one. They are committed rather than planted in .github/workflows/ at
# runtime so no cleanup failure can leave a probe workflow in the live tree.
#
# Extend: add a fixture directory with its own .github/workflows/ and a README
# stating which bypass it encodes, then a policy_ line here.

policy_() {  # policy_ <expected-exit> <fixture> <subcommand>
    local want="$1" fixture="$2" cmd="$3"
    case_ "$want" "policy $cmd: $fixture" \
        env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd"
}

# policy_msg_ <fixture> <subcommand> <grep-ere> -- red, and red for the STATED
# reason.
#
# Exit status alone cannot tell a finding from a crash: an uncaught
# AttributeError also exits 1, so a fixture asserting only `1` stays green when
# the branch it covers is replaced by a traceback. That is not hypothetical --
# deleting the `isinstance(spec, dict)` guard in check_secrets() made
# secrets-untyped die on `None.get()` and every exit-1 control still passed.
# Use this wherever the guard under test is what stops a crash.
#
# Captured first, not piped: pipefail would hand the pipeline the checker's
# exit 1 and the assertion would read as failed whatever the message said.
policy_msg_() {
    local fixture="$1" cmd="$2" want_re="$3" out got
    out="$(env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd" 2>&1)"; got=$?
    if [ "$got" -eq 1 ] && printf '%s\n' "$out" | grep -qE "$want_re"; then
        echo "ok   policy $cmd: $fixture (finding, not a crash)"
    else
        echo "FAIL policy $cmd: $fixture: expected exit 1 matching /$want_re/, got $got" >&2
        printf '%s\n' "$out" | sed 's/^/       | /' >&2
        rc=1
    fi
}

# policy_absent_ <fixture> <subcommand> <grep-ere> -- the pattern must NOT
# appear in the checker's output, whatever the exit code. Exit status alone
# cannot tell "no claimant" from "a claimant nobody collided with": if the
# name test ever degrades to a prefix match, a phantom band gets registered
# with a single, uncontested claimant, so exit and the primary message stay
# exactly as expected while a value that was supposed to be untouched shows
# up anyway. Assert its absence directly.
policy_absent_() {
    local fixture="$1" cmd="$2" absent_re="$3" out
    out="$(env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd" 2>&1)"
    if printf '%s\n' "$out" | grep -qE "$absent_re"; then
        echo "FAIL policy $cmd: $fixture: pattern /$absent_re/ unexpectedly present" >&2
        printf '%s\n' "$out" | sed 's/^/       | /' >&2
        rc=1
    else
        echo "ok   policy $cmd: $fixture (pattern absent: /$absent_re/)"
    fi
}

# THE control that makes the rest mean anything: a fixture tree that is simply
# a valid workflow must be GREEN on all three. Without it, a red on any bypass
# fixture could be the fixture shape rather than the bypass.
policy_ 0 clean runners
policy_ 0 clean ports
policy_ 0 clean docs
# Deliberately NO `policy_ 0 clean cadence`: the clean fixture has no
# workflow_call member, so that line would assert green over an empty set --
# vacuous, and indistinguishable from the check being broken. The green control
# for cadence is member-with-push-ok below, which has a member to clear.

# A `.yaml` workflow was invisible to every check: unchecked runner, unchecked
# ports, undocumented gate.
policy_ 1 bypass-yaml-extension runners
policy_ 1 bypass-yaml-extension docs

# `on: [pull_request]` / `on: pull_request` are the same trigger as the mapping
# form; both used to skip the runner-trust check, as did an inline
# pull_request_target.
policy_ 1 bypass-inline-events runners

# `runtime:  # comment` used to yield zero jobs, so a runtime-bearing job with
# no port band reported "no runtime-bearing jobs" and exit 0.
policy_ 1 bypass-commented-job-key ports

# A band verifier placed BELOW the first binder. Declaration, pass-through and
# uniqueness all hold, so the presence checks stay green -- this repo's own
# build-test.yml sat in exactly this shape until 2026-08-02.
policy_ 1 verify-after-bind ports

# A job whose only binder is `prove` (not ci/tools/test_runtime.py) used to be
# exempt from the "declare TEST_BASE_PORT" requirement, even though `prove` is
# already a BINDERS member and the ordering check already treats it as one.
# Found downstream as a failed negative control: deleting a prove-only job's
# band left this check green.
policy_ 1 prove-only-binder-exempt ports

# Composite-action port checking must be at ACTION granularity, mirroring the
# job-level treatment above -- not per-step, which cannot see an action-level
# `env:` or a declaration made in a sibling step, and cannot enforce the
# verifier-precedes-binder order rule inside `runs.steps` at all.
policy_ 0 action-level-env-declared ports
policy_ 0 action-cross-step-declare-bind ports

# The same action-level-env false positive one level up: a WORKFLOW-level
# `env:` sits on `doc`, above every job node, so a job's own body dump alone
# cannot see it either.
policy_ 0 workflow-level-env-declared ports

# The trap in fixing the above: registering the shared workflow-level band
# once per JOB instead of once per FILE turns N jobs sharing one declaration
# into a self-collision generator. Two jobs, one workflow-level
# TEST_BASE_PORT, must stay clean.
policy_ 0 workflow-level-env-shared-two-jobs ports

# Two composite actions are both named action.yml, so a `where` built from
# `path.name` alone names the same string for both sides of a collision and
# identifies neither. Assert the message actually distinguishes them by path.
policy_msg_ action-band-collision ports \
    'actions/second/action\.yml claims TEST_BASE_PORT 19830 and .*actions/first/action\.yml claims TEST_BASE_PORT 19830'

# A plain multi-line `run:` block, which an earlier version of this check
# could not reach: it scraped the node re-serialized by yaml.safe_dump, whose
# scalar style varies with the text's content. Also exercises the same-node
# "claims ... twice" wording for a collision between two steps of ONE action.
policy_msg_ action-inline-port-collision-plain ports \
    'claims AC_TEST_PORT 18500 twice across its steps'

# Only an assignment at the head of a line claims a band. A prefixed variable
# (SAVED_AC_TEST_PORT=), a diagnostic echo, a commented-out old band and a
# message string all mention the token without claiming the port; counting
# them folds phantom claimants into the uniqueness set and reddens a correct
# tree.
policy_ 0 action-inline-port-prefixed-identifier ports

# `env VAR=val cmd` is idiomatic for setting a port for one invocation and
# must be counted. An assignment introduced by a shell keyword is the
# documented limitation of walking only each line's assignment prefix; the
# green control pins it so the gap stays reviewed rather than silent.
policy_ 1 action-inline-port-env-prefix ports

# A single-line `run:` scalar, and two assignments sharing one line. Both were
# invisible while this check scraped the re-serialized node body.
policy_ 1 action-inline-port-single-line-run ports

# A quoted value claims the same band; a longer name that merely starts with
# the token (AC_TEST_PORTABLE) is a different variable and claims nothing.
policy_msg_ action-inline-port-quoted-value ports \
    'claims AC_TEST_PORT 18501 and .*claims AC_TEST_PORT 18501'
# The fixture's README also promises 18500 (AC_TEST_PORTABLE's value) never
# registers as a band -- unasserted, that half degrades silently: if the name
# test ever slid to a prefix match, AC_TEST_PORTABLE would register a phantom
# 18500 band with one uncontested claimant, raise no collision, and leave
# exit and the 18501 message untouched.
policy_absent_ action-inline-port-quoted-value ports '\b18500\b'
policy_ 0 action-inline-port-keyword-lead ports

# Direct master `push:` and `schedule:` are deliberate member entry points;
# neither duplicates the PR invocation. These green controls ensure cadence
# remains focused on a second `pull_request:` trigger.
policy_ 0 member-with-push cadence
policy_ 0 member-with-push-ok cadence
policy_ 1 member-with-pull-request cadence

# The three ways a secret goes missing between a caller and a member, none of
# which fails anything at the time it is introduced. `inherit` is green and
# merely over-broad; an untyped declaration starts the call with an empty
# string; an undeclared secret is dropped at the boundary while both halves
# read as correct in isolation. These run as a GROUP with secrets-typed-ok:
# this repo declares no secrets, so without a green fixture that DOES, the
# three reds would be equally consistent with "any mention of a secret is
# flagged" -- and the live check would be asserting green over an empty set.
policy_ 1 secrets-inherit secrets
# The same defect one repository over. The caller loop filtered to local
# members BEFORE judging `inherit`, so a call to
# `owner/repo/.github/workflows/x.yml@ref` was skipped -- the case where
# `inherit` is WORST, since the secret set crosses a repository boundary to a
# moving ref. Distinct from secrets-inherit: reordering that filter back below
# the inherit branch leaves the local fixture red and only this one green.
policy_ 1 secrets-inherit-external secrets
# The third case that filter used to swallow: an external call whose `secrets:`
# is neither a mapping nor `inherit`. `inherit` was hoisted above the filter,
# but the SHAPE check stayed below it, so `secrets: false` on an external member
# reported clean over a caller GitHub refuses to start. Exit 2, not 1 -- an
# uninterpretable `secrets:` means the check did not run over that call, so
# policy_msg_ (which hardcodes exit 1) cannot assert this one. Moving the shape
# check back below `if not local` turns this fixture green while every other
# secrets fixture stays exactly as it is.
policy_ 2 secrets-malformed-external secrets
# Message-asserted: a null spec is exactly the input that crashes `.get()` if
# the isinstance guard is removed, and a traceback also exits 1.
policy_msg_ secrets-untyped secrets 'declares secret .* untyped'
# secrets-optional is NOT redundant with secrets-untyped. Disarming the
# `required is not True` test left secrets-untyped red anyway -- it trips the
# missing-key branch -- so the value test had no control of its own. A mutant
# that survives is a branch nothing is gating.
policy_ 1 secrets-optional secrets
# ...and secrets-no-required-key is not redundant with EITHER. `NAME:` with
# nothing under it parses to null, and null `is not True`, so the value branch
# covers secrets-untyped even when the missing-key branch is deleted. Only a
# spec that is a real mapping without the key separates the two.
policy_ 1 secrets-no-required-key secrets
policy_ 1 secrets-undeclared secrets
# The mirror of secrets-undeclared, and the direction the check missed when
# first written: member requires it, caller wires nothing.
policy_ 1 secrets-required-not-wired secrets
policy_ 0 secrets-typed-ok secrets

# A mistyped pool label in a schedule-only workflow. The trust half of the
# runners check does not apply to a workflow no fork can reach, and skipping it
# used to skip the LABEL membership test with it -- while actionlint, the only
# other thing that reads runner labels, stays silent on the `fromJSON(...)`
# selectors this repo uses everywhere. Six selectors in bump.yml and ci-deep.yml
# had no label checking at all. These two run as a PAIR: the -ok fixture is the
# same file spelled correctly, and without it the red below is equally
# consistent with "every non-PR-reachable workflow is now flagged".
policy_ 1 schedule-only-runner-labels runners
policy_ 0 schedule-only-runner-labels-ok runners

# WIRING CONTROLS. These assert that a checker is reachable at all, which is a
# weaker claim than "it goes red on a defect" -- the red-direction probes need
# real tools and live in each checker's header instead, so this file keeps its
# no-linter-required property. They exist because both failures below were
# silent: a checker nobody dispatches and a hook nobody runs look exactly like a
# clean tree.
#
# core.hooksPath REPLACES .git/hooks/, so `pre-commit install` writes a file git
# never reads. Measured 2026-08-02: trailing whitespace and a missing final
# newline committed clean past the hooks whose only job is those two things.
# .githooks/pre-commit therefore has to invoke pre-commit itself.
case_ 0 "the commit hook invokes the pre-commit-config hooks" \
    grep -q '^ *pre-commit run' .githooks/pre-commit

# run-all.sh dispatches by glob, so a checker that is not executable, or is
# named outside the lint-*.sh pattern, is silently not run.
# Every glob-discovered checker is named in lint.yml's LINT_ONLY.
#
# run-all.sh picks checkers up by glob, but CI narrows the run to an explicit
# allowlist, and nothing connected the two: a checker added to ci/linter/ ran
# locally and in the pre-commit hook while being silently absent from every PR.
# That is not a hypothetical -- ci-cadence shipped in 2026-08-06 and had never
# run remotely when this control was written. A gate that runs everywhere except
# the merge path is the one place it is load-bearing.
missing=""
only="$(sed -n 's/^ *LINT_ONLY: *//p' .github/workflows/lint.yml)"

# Checkers knowingly absent from lint.yml's LINT_ONLY. Listed HERE, explicitly,
# so the control still fails on an ACCIDENTAL omission -- the case it exists
# for -- while a deliberate one costs an edit to this line and shows up in the
# diff. The reason is spelled out in lint.yml's header:
#   c  permanent -- security-scanners.yml already scans src/
# This list must only ever SHRINK.
staged_out="c"

for s in ci/linter/lint-*.sh; do
    n="${s#ci/linter/lint-}"; n="${n%.sh}"
    printf '%s\n' "$staged_out" | tr ' ' '\n' | grep -qx "$n" && continue
    printf '%s\n' "$only" | tr ' ' '\n' | grep -qx "$n" || missing="$missing $n"
done
if [ -z "$missing" ]; then
    echo "ok   every checker is named in lint.yml LINT_ONLY"
else
    echo "FAIL checkers absent from lint.yml LINT_ONLY:$missing" >&2
    echo "       | they run locally and in the hook, but never on a PR" >&2
    rc=1
fi

case_ 0 "lint-spelling is dispatched by run-all.sh" \
    bash -c 'ci/linter/run-all.sh --list | grep -q lint-spelling.sh'

# Unparsable YAML is "could not run" (2), never "clean" -- GitHub may still
# read a file this parser rejects, so a verdict over the rest of the tree would
# be unsupported. Fixture is generated: a committed broken-YAML file would trip
# yamllint on the real tree.
badroot="$(mktemp -d)"
trap 'rm -rf "$badroot"' EXIT
mkdir -p "$badroot/.github/workflows"
printf 'on: [pull_request\njobs: {\n' > "$badroot/.github/workflows/broken.yml"
case_ 2 "policy runners: unparsable YAML is exit 2, not clean" \
    env "WORKFLOW_POLICY_ROOT=$badroot" python3 ci/linter/workflow_policy.py runners

# lint-yaml gates on FINDING SEVERITY, not on yamllint's exit status: yamllint
# is unpinned and switches to `-f github` on a runner, and the exit code it
# pairs with a warnings-only run has differed between builds. Both directions
# are controlled here -- a warnings-only file must pass, an error-level file
# must fail -- so a future "|| rc=1" cannot quietly re-red the gate on
# warnings, and no rewrite can quietly stop blocking real errors.
yamlroot="$(mktemp -d)"
trap 'rm -rf "$badroot" "$yamlroot"' EXIT
# Long line + one-space comment: [warning] only under this repo's .yamllint.
{
    printf 'key: %s # one-space comment\n' "$(printf 'x%.0s' $(seq 1 130))"
} > "$yamlroot/warn.yml"
case_ 0 "lint-yaml: warning-only YAML passes the gate" \
    bash -c "cd '$PWD' && ci/linter/lint-yaml.sh '$yamlroot/warn.yml'"

printf 'a: 1\na: 2\n' > "$yamlroot/err.yml"
case_ 1 "lint-yaml: error-level YAML fails the gate" \
    bash -c "cd '$PWD' && ci/linter/lint-yaml.sh '$yamlroot/err.yml'"

# lint-ca-log-safety: whitespace-tolerant &r->url detection.
#
# lint_files() matches only '^src/.*\.[ch]$' and, given explicit args, filters
# on the string alone without consulting git -- so a fixture rooted under a
# throwaway '<tmp>/src/...' satisfies the selector as long as the linter's
# cwd resolves that tmp dir as its git toplevel (it sources lib.sh via
# `git rev-parse --show-toplevel`). Build a scratch git repo with its own
# src/ and a copied lib.sh so nothing here touches the real tree or git index.
calogroot="$(mktemp -d)"
trap 'rm -rf "$badroot" "$yamlroot" "$calogroot"' EXIT
mkdir -p "$calogroot/src" "$calogroot/ci/linter"
cp "$ROOT/ci/linter/lib.sh" "$calogroot/ci/linter/lib.sh"
git -C "$calogroot" init -q .

calog_case() {
    # calog_case <expected-exit> <description> <statement-body>
    local expect="$1" desc="$2" body="$3"
    cat > "$calogroot/src/fixture.c" <<EOF
void f(ngx_http_request_t *r) {
    $body
}
EOF
    case_ "$expect" "$desc" \
        bash -c "cd '$calogroot' && bash '$ROOT/ci/linter/lint-ca-log-safety.sh' src/fixture.c"
}

calog_case 1 "lint-ca-log-safety: literal &r->url is caught" \
    'ngx_log_error(NGX_LOG_ERR, r->log, 0, "%V", &r->url);'
calog_case 1 "lint-ca-log-safety: '& r->url' spacing is caught" \
    'ngx_log_error(NGX_LOG_ERR, r->log, 0, "%V", & r->url);'
calog_case 1 "lint-ca-log-safety: '&r -> url' spacing is caught" \
    'ngx_log_error(NGX_LOG_ERR, r->log, 0, "%V", &r -> url);'
calog_case 1 "lint-ca-log-safety: '&r->    url' spacing is caught" \
    'ngx_log_error(NGX_LOG_ERR, r->log, 0, "%V", &r->    url);'
calog_case 0 "lint-ca-log-safety: wrapped call still passes" \
    'ngx_log_error(NGX_LOG_ERR, r->log, 0, "%V", ngx_autocert_acme_log_safe(&r->url));'
calog_case 0 "lint-ca-log-safety: debug level stays exempt" \
    'ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%V", &r->url);'
calog_case 1 "lint-ca-log-safety: 'not ngx_log_debug' comment does not exempt an ERROR call" \
    'ngx_log_error(NGX_LOG_ERR, r->log, 0, /* not ngx_log_debug */
                  "%V", &r->url);'
calog_case 0 "lint-ca-log-safety: helper call with space before its paren is still stripped" \
    'ngx_log_error(NGX_LOG_ERR, r->log, 0, "%V", ngx_autocert_acme_log_safe (r->pool, &r->url));'

if [ "$rc" -eq 0 ]; then
    echo "== lint gate selftest: all controls held =="
else
    echo "== lint gate selftest: FAILED ==" >&2
fi
exit "$rc"
