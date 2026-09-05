#!/usr/bin/env bash
#
# Container image pins for the e2e suite.
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Pebble and challtestsrv are pulled from a mutable `:latest` tag upstream.
# A silent retag there changes the ACME server under every e2e test at once,
# which turns an upstream release into an unexplained red suite -- and, worse,
# can make a green suite meaningless because it exercised a different server
# than the one it claims to. Pin both by digest so the CA under test is a
# reproducible input, and bump these two lines deliberately.
#
# The tag is kept alongside the digest purely so a human can see which release
# a digest corresponds to; docker resolves on the digest and ignores it.
#
# To bump:
#   docker buildx imagetools inspect ghcr.io/letsencrypt/pebble:latest
#   docker buildx imagetools inspect ghcr.io/letsencrypt/pebble-challtestsrv:latest
# then replace the digests below and run the full e2e suite.

# This file is only ever sourced, so shellcheck cannot see the consumers.
# shellcheck disable=SC2034

# Resolved 2026-09-05 from ghcr.io/letsencrypt/pebble:latest
PEBBLE_IMAGE="ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"

# Resolved 2026-09-05 from ghcr.io/letsencrypt/pebble-challtestsrv:latest
CHALLTESTSRV_IMAGE="ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b"
