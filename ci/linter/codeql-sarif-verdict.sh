#!/usr/bin/env bash
# Return non-zero when any SARIF result has blocking CodeQL severity.

set -euo pipefail

count=0
for sarif in "$@"; do
	if ! n="$(jq -e '
             if (.runs | type) != "array"
                or (.runs | length) == 0
                or any(.runs[]; (.results | type) != "array")
             then error("each SARIF run must contain a results array")
             else [.runs[]
               | . as $run
               | .results[]
               | . as $r
               | ( [ $run.tool.driver.rules[]?
                     | select(.id == $r.ruleId) ][0]
                   // ($r.ruleIndex as $i
                       | if $i == null then null
                         else $run.tool.driver.rules[$i] end)
                   // {} ) as $rule
               | select(
                   ($r.level
                    // $rule.defaultConfiguration.level?
                    // "warning") == "error"
                   or $rule.properties["problem.severity"]? == "error"
                   or $rule.properties["security-severity"]? != null
                 )] | length
             end' "$sarif")"; then
		echo "::error::invalid SARIF output: $sarif" >&2
		exit 2
	fi
	count=$((count + n))
done

echo "blocking CodeQL findings: $count"
if [ "$count" -gt 0 ]; then
	echo "::error::$count blocking CodeQL finding(s) -- see the Security tab for /language:c-cpp"
	exit 1
fi
