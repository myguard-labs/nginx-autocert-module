#!/bin/bash
# Linter: Check for documentation drift.
#
# Verifies that documentation references to CI workflows, test paths, and build
# paths match the actual files and directory structure.

set -e

cd "$(git rev-parse --show-toplevel)"

rc=0

# Check 1: .github/CI.md exists and references valid workflow files.
if [ ! -f ".github/CI.md" ]; then
	echo "ERROR: .github/CI.md does not exist" >&2
	rc=1
else
	# Extract filenames from the CI.md workflow table (e.g., "build-test.yml").
	while IFS= read -r workflow; do
		# Skip table header and separators
		[[ "$workflow" =~ ^[\|\ ]*$ ]] && continue
		[[ "$workflow" =~ Workflow ]] && continue

		# Extract workflow filename (e.g., "build-test.yml" from "| `build-test.yml` |")
		if [[ "$workflow" =~ \`([a-z\-]+\.yml)\` ]]; then
			wf="${BASH_REMATCH[1]}"
			if [ ! -f ".github/workflows/$wf" ]; then
				echo "ERROR: .github/CI.md references workflow $wf which does not exist" >&2
				rc=1
			fi
		fi
	done <.github/CI.md
fi

# Check 2: ci/fuzz/README.md path references are correct.
# Verify that ci/fuzz paths in the README point to real directories/files.
if ! grep -q "ci/fuzz/build.sh" ci/fuzz/README.md; then
	echo "ERROR: ci/fuzz/README.md does not reference ci/fuzz/build.sh" >&2
	rc=1
fi

if ! grep -q "ci/tests/unit/test_http.c" ci/fuzz/README.md; then
	echo "ERROR: ci/fuzz/README.md does not reference ci/tests/unit/test_http.c" >&2
	rc=1
fi

# Verify ci/fuzz/build.sh exists
if [ ! -f "ci/fuzz/build.sh" ]; then
	echo "ERROR: ci/fuzz/build.sh does not exist" >&2
	rc=1
fi

# Verify test paths exist
if [ ! -f "ci/tests/unit/test_http.c" ]; then
	echo "ERROR: ci/tests/unit/test_http.c does not exist" >&2
	rc=1
fi

# Check 3: Local validation commands in CI.md match actual test paths.
if grep -q "ci/tests/e2e/" .github/CI.md; then
	if [ ! -d "ci/tests/e2e" ]; then
		echo "ERROR: .github/CI.md references ci/tests/e2e/ but the directory does not exist" >&2
		rc=1
	fi
fi

if grep -q "ci/tests/unit/" .github/CI.md; then
	if [ ! -d "ci/tests/unit" ]; then
		echo "ERROR: .github/CI.md references ci/tests/unit/ but the directory does not exist" >&2
		rc=1
	fi
fi

if [ $rc -eq 0 ]; then
	echo "Documentation drift check passed" >&2
fi

exit $rc
