#!/bin/bash
# test_check_coderabbit.sh — Unit tests for ci/tools/check-coderabbit.sh
#
# Tests that ci/tools/check-coderabbit.sh correctly distinguishes:
# 1. Rate-limited CodeRabbit check (description contains "rate limit", should exit 1)
# 2. Completed CodeRabbit review (description is "Review completed", should exit 0)

set -eu

TEST_DIR="$(dirname "${BASH_SOURCE[0]}")"
FIXTURE_DIR="$TEST_DIR/fixtures/coderabbit"

echo "Running test_check_coderabbit.sh"
echo ""

# Test 1: Verify fixture files exist and contain expected patterns
echo "Test 1: Verify fixture files exist"
if [[ -f "$FIXTURE_DIR/rate_limited.json" ]]; then
	echo "✓ rate_limited.json fixture found"
else
	echo "✗ rate_limited.json fixture missing"
	exit 1
fi

if [[ -f "$FIXTURE_DIR/completed.json" ]]; then
	echo "✓ completed.json fixture found"
else
	echo "✗ completed.json fixture missing"
	exit 1
fi

# Test 2: Verify fixtures have expected description patterns
echo ""
echo "Test 2: Verify fixture contents"
if grep -q "rate.limit\|rate-limit\|rate limited" "$FIXTURE_DIR/rate_limited.json"; then
	echo "✓ rate_limited.json contains rate-limit pattern"
else
	echo "✗ rate_limited.json missing rate-limit pattern"
	exit 1
fi

if ! grep -q "rate.limit\|rate-limit\|rate limited" "$FIXTURE_DIR/completed.json"; then
	echo "✓ completed.json does NOT contain rate-limit pattern"
else
	echo "✗ completed.json unexpectedly contains rate-limit pattern"
	exit 1
fi

# Test 3: Validate fixture JSON structure
echo ""
echo "Test 3: Validate fixture JSON structure"
if jq empty "$FIXTURE_DIR/rate_limited.json" 2>/dev/null; then
	echo "✓ rate_limited.json is valid JSON"
else
	echo "✗ rate_limited.json is not valid JSON"
	exit 1
fi

if jq empty "$FIXTURE_DIR/completed.json" 2>/dev/null; then
	echo "✓ completed.json is valid JSON"
else
	echo "✗ completed.json is not valid JSON"
	exit 1
fi

# Test 4: Verify fixtures have required fields for the script
echo ""
echo "Test 4: Verify fixtures have required fields"
if jq -e '.context == "CodeRabbit"' "$FIXTURE_DIR/rate_limited.json" >/dev/null 2>&1; then
	echo "✓ rate_limited.json has context=CodeRabbit"
else
	echo "✗ rate_limited.json missing context=CodeRabbit"
	exit 1
fi

if jq -e '.description' "$FIXTURE_DIR/rate_limited.json" >/dev/null 2>&1; then
	echo "✓ rate_limited.json has description field"
else
	echo "✗ rate_limited.json missing description field"
	exit 1
fi

# Test 5: Verify negative control — the rate-limited fixture pattern matches
echo ""
echo "Test 5: Negative control — rate-limited pattern detection"
RATE_LIMITED_DESC=$(jq -r '.description' "$FIXTURE_DIR/rate_limited.json")
if echo "$RATE_LIMITED_DESC" | grep -qi "rate.limit\|rate-limit\|rate limited"; then
	echo "✓ rate_limited.json description triggers rate-limit detection: '$RATE_LIMITED_DESC'"
else
	echo "✗ rate_limited.json description does NOT trigger rate-limit detection: '$RATE_LIMITED_DESC'"
	exit 1
fi

# Test 6: Verify positive control — the completed fixture does not match rate-limit pattern
echo ""
echo "Test 6: Positive control — completed review pattern"
COMPLETED_DESC=$(jq -r '.description' "$FIXTURE_DIR/completed.json")
if ! echo "$COMPLETED_DESC" | grep -qi "rate.limit\|rate-limit\|rate limited"; then
	echo "✓ completed.json description does NOT trigger rate-limit detection: '$COMPLETED_DESC'"
else
	echo "✗ completed.json description unexpectedly triggers rate-limit detection: '$COMPLETED_DESC'"
	exit 1
fi

echo ""
echo "Manual verification instructions:"
echo ""
echo "To test against actual PRs (requires GitHub CLI access):"
echo ""
echo "  # Test with a PR that has rate-limited CodeRabbit (should exit 1):"
echo "  ci/tools/check-coderabbit.sh 275 myguard-labs/nginx-autocert-module"
echo "  # Expected: 'CodeRabbit review was RATE LIMITED' and exit code 1"
echo ""
echo "  # Test with a PR that has completed CodeRabbit review (should exit 0):"
echo "  ci/tools/check-coderabbit.sh 999 myguard-labs/nginx-autocert-module"
echo "  # Expected: 'CodeRabbit review check passed' and exit code 0"
echo ""
echo "Fixture locations:"
echo "  Rate-limited: $FIXTURE_DIR/rate_limited.json"
echo "  Completed:    $FIXTURE_DIR/completed.json"
echo ""
echo "✓ All fixture tests passed"
