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
               | ($run.tool.driver.rules // []) as $rules
               | (if $r.ruleIndex != null
                  then $r.ruleIndex as $i
                    | if ($i | type) != "number"
                         or ($i | floor) != $i
                         or $i < 0
                         or $i >= ($rules | length)
                      then error("ruleIndex must be an in-range nonnegative integer")
                      elif $r.ruleId != null
                           and (($r.ruleId == $rules[$i].id
                                 or (($r.ruleId | type) == "string"
                                     and ($rules[$i].id | type) == "string"
                                     and ($r.ruleId
                                          | startswith($rules[$i].id + "/"))
                                     and ($r.ruleId
                                          | ltrimstr($rules[$i].id + "/")
                                          | . as $suffix
                                          | ($suffix | length > 0)
                                            and ($suffix | contains("/") | not))))
                                | not)
                      then error("ruleId does not match the indexed rule")
                      else $rules[$i]
                      end
                  else ([ $rules[]? | select(.id == $r.ruleId) ][0] // {})
                  end) as $rule
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
