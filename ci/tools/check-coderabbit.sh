#!/bin/bash
# check-coderabbit.sh — Verify CodeRabbit review status before merge.
#
# CodeRabbit reports rate-limited reviews as "pass", making them indistinguishable
# from a real review. This script checks the status check's description string
# to detect when the review was skipped due to rate limiting.
#
# Usage:
#   ci/tools/check-coderabbit.sh <PR_NUMBER> [REPO]
#
# Arguments:
#   PR_NUMBER       GitHub PR number (required)
#   REPO            GitHub repository (optional; default: myguard-labs/nginx-autocert-module)
#
# Exit codes:
#   0               Review was completed (description does not mention rate limit)
#   1               Review was rate-limited (description contains "rate limit" or similar)
#   2               Script error (PR not found, no CodeRabbit check, etc.)

set -eu

# Argument validation
if [[ $# -lt 1 ]]; then
	echo "Usage: $0 <PR_NUMBER> [REPO]" >&2
	exit 2
fi

PR_NUMBER="$1"
REPO="${2:-myguard-labs/nginx-autocert-module}"

# Get the PR's head commit SHA
HEAD_SHA=$(gh pr view "$PR_NUMBER" -R "$REPO" --json commits --jq '.commits[-1].oid' 2>/dev/null || true)

if [[ -z "$HEAD_SHA" ]]; then
	echo "Error: Could not fetch PR $PR_NUMBER from $REPO" >&2
	exit 2
fi

# Fetch the commit status to get the CodeRabbit description
# The commit status API includes the description field which is not in the PR view's statusCheckRollup
CODERABBIT_STATUS=$(gh api "repos/$REPO/commits/$HEAD_SHA/status" --jq '.statuses[] | select(.context == "CodeRabbit")' 2>/dev/null || true)

if [[ -z "$CODERABBIT_STATUS" ]]; then
	echo "Error: No CodeRabbit check found for PR $PR_NUMBER (commit: $HEAD_SHA)" >&2
	exit 2
fi

# Extract the description field from the CodeRabbit status
DESCRIPTION=$(echo "$CODERABBIT_STATUS" | jq -r '.description // ""' 2>/dev/null || true)

# Check if the description mentions rate limiting
if echo "$DESCRIPTION" | grep -qi "rate.limit\|rate-limit\|rate limited"; then
	echo "CodeRabbit review was RATE LIMITED: $DESCRIPTION" >&2
	exit 1
fi

# Review appears to have completed (or no description indicates no rate limit)
if [[ -z "$DESCRIPTION" ]]; then
	echo "CodeRabbit review check passed (no rate limit detected)"
else
	echo "CodeRabbit review check passed: $DESCRIPTION"
fi
exit 0
