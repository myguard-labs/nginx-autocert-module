#!/bin/bash
# Test: Verify corpus gitignore policies work correctly.
#
# Each corpus directory has a policy: named seeds are tracked, libFuzzer-
# discovered (40-hex) units are ignored and transient. This test verifies:
# 1. All named seeds are tracked in git.
# 2. All patterns allow hex-named generated units to be untracked.

set -e

cd "$(git rev-parse --show-toplevel)"

# Named corpus seeds that MUST be tracked.
declare -a NAMED_SEEDS=(
	# HTTP corpus
	ci/fuzz/corpus_http/bad_code
	ci/fuzz/corpus_http/bad_ver
	ci/fuzz/corpus_http/big_chunk
	ci/fuzz/corpus_http/chunked
	ci/fuzz/corpus_http/cl_ok
	ci/fuzz/corpus_http/created
	ci/fuzz/corpus_http/junk
	ci/fuzz/corpus_http/notfound
	# Base64 corpus
	ci/fuzz/corpus_b64/all_dash_underscore
	ci/fuzz/corpus_b64/eab_hmac_key_32
	ci/fuzz/corpus_b64/empty
	ci/fuzz/corpus_b64/exact_4char
	ci/fuzz/corpus_b64/has_newline
	ci/fuzz/corpus_b64/has_null_byte
	ci/fuzz/corpus_b64/has_padding_equals
	ci/fuzz/corpus_b64/has_space
	ci/fuzz/corpus_b64/has_std_b64_plus
	ci/fuzz/corpus_b64/has_std_b64_slash
	ci/fuzz/corpus_b64/high_byte_0x80
	ci/fuzz/corpus_b64/jws_payload_empty
	ci/fuzz/corpus_b64/jws_payload_order
	ci/fuzz/corpus_b64/jws_protected_header
	ci/fuzz/corpus_b64/jws_signature_ecdsa
	ci/fuzz/corpus_b64/len_mod4_eq1
	ci/fuzz/corpus_b64/mixed_valid_invalid
	ci/fuzz/corpus_b64/short_1char
	ci/fuzz/corpus_b64/short_2char
	ci/fuzz/corpus_b64/short_3char
	ci/fuzz/corpus_b64/utf8_multibyte
	ci/fuzz/corpus_b64/very_long_valid
	# JSON corpus
	ci/fuzz/corpus/account.json
	ci/fuzz/corpus/authz.json
	ci/fuzz/corpus/deep_nest.json
	ci/fuzz/corpus/directory.json
	ci/fuzz/corpus/empty_obj.json
	ci/fuzz/corpus/escapes.json
	ci/fuzz/corpus/numbers.json
	ci/fuzz/corpus/order.json
	ci/fuzz/corpus/truncated.json
	ci/fuzz/corpus/unicode.json
)

# Verify all named seeds exist and are tracked.
for seed in "${NAMED_SEEDS[@]}"; do
	if ! git ls-files --error-unmatch "$seed" >/dev/null 2>&1; then
		echo "FAIL: named seed $seed is not tracked in git" >&2
		exit 1
	fi
	if [ ! -f "$seed" ]; then
		echo "FAIL: named seed $seed does not exist" >&2
		exit 1
	fi
done

# Verify hex-named files would be ignored by .gitignore.
# Use git check-ignore to verify the gitignore policy is active for each corpus.
for corpus_dir in ci/fuzz/corpus_http ci/fuzz/corpus_b64; do
	test_name="${corpus_dir}/0123456789abcdef0123456789abcdef01234567"

	# Verify git check-ignore returns match (status 0) for the hex-named path.
	if ! git check-ignore "$test_name" >/dev/null 2>&1; then
		echo "FAIL: .gitignore does not match hex-named pattern in $corpus_dir" >&2
		exit 1
	fi
done

echo "all tests passed"
exit 0
