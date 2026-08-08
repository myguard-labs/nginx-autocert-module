#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-sync-stamp.sh -- every skeleton-shared .github/ file carries a
# current content stamp.
#
# The mechanism and the reasoning live in ci/tools/sync-stamp.sh; this wrapper
# exists so run-all.sh picks the check up by glob and LINT_ONLY=sync-stamp
# selects it.
#
# What it prevents: a stamp that rots into decoration. The stamps only answer
# "has this adopter's copy drifted from the skeleton" for as long as they track
# the content they claim to describe, and an edit that skips re-stamping breaks
# that silently -- the file is still stamped, just with the previous file's sha,
# so a two-repo `--list` diff reports agreement that no longer holds.
#
# Usage: ci/linter/lint-sync-stamp.sh [files...]   Env: LINT_MODE=staged|all
# Extend: the scope (which files are stamped) is decided in sync-stamp.sh's
# targets(), not here.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '^\.github/(workflows/.*\.ya?ml|scripts/.*\.sh|actions/.*/action\.ya?ml)$' "$@")
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-sync-stamp: no stamped files to check"; exit 0; }

# Whole-tree by nature: --check walks its own target set, so the file list only
# decides whether this checker is relevant to the change at hand.
exec "$(git rev-parse --show-toplevel)/ci/tools/sync-stamp.sh" --check
