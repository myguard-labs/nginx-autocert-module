#!/usr/bin/env bash

# Compose the sanitizer environment shared by the nginx soak and its harness
# self-test. The caller supplies the directory used for sanitizer reports.
autocert_sanitizer_env() {
    local log_dir="${1:?sanitizer log directory required}"

    # LSan parses LSAN_OPTIONS after ASAN_OPTIONS, so the setting must be in
    # both variables. Valgrind owns leak detection for this nginx workload;
    # ASan redzones/UAF and UBSan remain enabled.
    export LSAN_OPTIONS="${LSAN_OPTIONS:-}:detect_leaks=0"
    export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=0:detect_odr_violation=0:abort_on_error=0:exitcode=42:log_path=$log_dir/asan"
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=0:log_path=$log_dir/asan"
}
