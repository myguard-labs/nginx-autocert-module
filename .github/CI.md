# Continuous integration

The CI pipeline is intentionally split by feedback speed and failure class.
`ci.yml` is the sole PR entry point: it calls `build-test.yml`,
`security-scanners.yml`, `fuzzing.yml`, `lint.yml` and `codeql.yml`, so each
runs exactly once per PR. The rest are scheduled or manual only.

## Runs on every PR (via ci.yml)

| Workflow | Required check (exact name GitHub surfaces) | Coverage |
|---|---|---|
| `build-test.yml` | `Build&Test / Validation` | shell syntax, ShellCheck, cppcheck, whitespace, workflow lint |
| `build-test.yml` | `Build&Test / Resolve nginx + angie versions` | output plumbing only — pins the mainline nginx and Angie versions the build jobs consume |
| `build-test.yml` | `Build&Test / Build & load (nginx …)` † | latest mainline nginx build, module load, config rejection, no-network serve/lifecycle tests |
| `build-test.yml` | `Build&Test / Build & load (angie …)` † | latest Angie API compile drift guard |
| `build-test.yml` | `Build&Test / Guard suite` | config-rejection and lifecycle guard assertions |
| `build-test.yml` | `Build&Test / Unit tests` | JOSE, JWK, thumbprint, JWS signing, ACME JSON parser happy paths and malformed-input rejection |
| `build-test.yml` | `Build&Test / Unit tests (ASan+UBSan)` | the same unit suite under AddressSanitizer and UBSan |
| `build-test.yml` | `Build&Test / e2e suite (Pebble) [nginx]` † | Pebble account/order/issuance/renewal/backoff/rate-limit flows |
| `security-scanners.yml` | `Security scanners / Security scanners`, `Security scanners / gitleaks (full history)` | flawfinder gate plus clang-tidy and Semgrep reports |
| `fuzzing.yml` | `Fuzzing / Fuzz regression (30s/target)` | 30s/target libFuzzer run of the JSON/HTTP/base64url ACME parsers |
| `lint.yml` | `Lint / Linters` | ci/linter/ shell, nginx-convention and workflow-syntax checks (excludes the C lens; that's `security-scanners.yml`'s job) |
| `codeql.yml` | `CodeQL / Analyze C` | CodeQL security-extended C/C++ queries, SARIF uploaded to code scanning |

† These job names embed a `${{ }}` expression (the resolved nginx/Angie
version, or the e2e matrix flavor), so the surfaced check name changes with
the pin. Branch protection cannot match a name that moves — require the
stable checks above and treat these as informational, or pin them by the
`ci.yml` caller job (`Build&Test`) instead — noting that the caller job gates
every `build-test.yml` job at once, not only the daggered three.

`build-test.yml`, `codeql.yml` and `security-scanners.yml` also carry their own
bounded `push:`/`schedule:` triggers for direct master coverage; they
deliberately do not carry a standalone `pull_request:` since `ci.yml` already
calls them.

## Outside the `ci.yml` PR gate

| Workflow | Cadence | Coverage |
|---|---|---|
| `ci-deep.yml` | monthly (day 2) + release/dispatch | exhaustive fuzz (`FUZZ_SECS`, 3600s default), memcheck/helgrind soak, scanners, non-blocking coverage, angie Pebble e2e |
| `valgrind.yml` | manual dispatch | 30s Memcheck-lite soak of the HTTP-01 serve path |
| `asan.yml` | weekly (Sunday 03:45 UTC) + manual | 30s ASan/UBSan soak of the HTTP-01 serve path |
| `bump.yml` | weekly | checks nginx.org/angie.software for newer pins, opens a PR against `.github/versions.env` |
| `windows-build.yml` | every PR touching win32 paths + push | MSVC compile/link and a runtime HTTP-01 challenge-serve smoke test on Windows -- the one workflow here that DOES gate a PR, via its own path filter rather than `ci.yml` |

`fuzzing.yml`'s deep campaign lives in `ci-deep.yml` (`FUZZ_SECS`, 3600s
default); the per-PR `fuzzing.yml` run above is the fast 30s/target
regression only.

## Action pins

All third-party actions are pinned to immutable commit SHAs.
`.github/dependabot.yml` is the source of truth for these pins across
`.github/workflows/` and `.github/actions/*`; it opens a PR per bump. Workflow
headers no longer carry hand-maintained "keep in sync" pin tables — check
`.github/dependabot.yml` and the individual `uses:` lines instead.

Workflows use read-only repository permissions except CodeQL/SARIF upload
jobs, which also receive `security-events: write`.

## Local validation

```bash
bash -n ci/tests/e2e/*.sh ci/fuzz/*.sh ci/tests/unit/*.sh
shellcheck ci/tests/e2e/*.sh ci/fuzz/*.sh ci/tests/unit/*.sh
cppcheck \
  --enable=warning,performance,portability \
  --error-exitcode=1 \
  --suppress=missingIncludeSystem \
  --suppress=normalCheckLevelMaxBranches \
  --suppress=unusedFunction \
  src/*.c
git diff --check
```

Or run the same checks the pre-commit hook and `lint.yml` run:
`ci/linter/run-all.sh` (enable it locally with
`git config core.hooksPath .githooks`).
