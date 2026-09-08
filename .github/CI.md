# Continuous integration

The CI pipeline is intentionally split by feedback speed and failure class:

| Workflow | Required check | Coverage |
| --- | --- | --- |
| `build-test.yml` | `Validation` | syntax, ShellCheck, cppcheck, lint |
| `build-test.yml` | `Build & load` | nginx build, load, config, lifecycle |
| `build-test.yml` | `Compile-only` | Angie API compile drift guard |
| `build-test.yml` | `Crypto unit tests` | JOSE, JWK, thumbprint, JWS |
| `build-test.yml` | `JSON parser unit tests` | parser paths, malformed-input |
| `build-test.yml` | ACME e2e jobs | account/order/issuance/renewal/rate |
| `valgrind.yml` | `Memcheck` | Valgrind checks |
| `codeql.yml` | `Analyze C` | CodeQL C/C++ queries |
| `security-scanners.yml` | `Secure` | flawfinder, clang-tidy, Semgrep |
| `fuzzing.yml` | scheduled | monthly libFuzzer run |

All third-party actions are pinned to immutable commit SHAs. Workflows use
read-only repository permissions except CodeQL/SARIF upload jobs, which also
receive `security-events: write`.

`.github/dependabot.yml` is the source of truth for GitHub Action pins across
`.github/workflows/` and `.github/actions/*`; it opens a PR per bump. Workflow
headers no longer carry hand-maintained "keep in sync" pin tables — check
`.github/dependabot.yml` and the individual `uses:` lines instead.

## Merge gate validation

Before merging a PR, verify that the CodeRabbit check is not rate-limited:

```bash
ci/tools/check-coderabbit.sh <PR_NUMBER> myguard-labs/nginx-autocert-module
```

This script checks if CodeRabbit's review was skipped due to rate limiting.
A rate-limited check reports as "pass" even though no review actually ran,
which is indistinguishable from a genuine clean review. The script exits:

- **0** if the review was completed
- **1** if the review was rate-limited (do not merge)
- **2** if there is a script error

See also: [CodeRabbit rate-limit detection](#coderabbit-rate-limit-detection)

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

## CodeRabbit rate-limit detection

CodeRabbit is subject to rate limiting. When rate-limited, it reports the check
as "SUCCESS" / "pass" with description "Review rate limited" — indistinguishable
from a real review. This creates a merge gate gap.

The `ci/tools/check-coderabbit.sh` script detects this by reading the check's
description via the GitHub API. Before merging a production PR, run:

```bash
ci/tools/check-coderabbit.sh <PR_NUMBER> myguard-labs/nginx-autocert-module
```

If the exit code is 1, the bot hit its rate limit. Options:

1. **Wait** — Rate limits typically clear within hours; re-run to check.
2. **Manual review** — Have a reviewer approve and document the skip.
3. **Record the gap** — Note in the PR body that CodeRabbit was skipped.

Scheduled CI jobs do not run CodeRabbit; this applies to on-demand PRs
only.
