#!/usr/bin/env bash
#
# Every `FROM rust:<ver>` in a Dockerfile must agree with rust-toolchain.toml.
#
# rust-toolchain.toml is excluded from the Docker build context (.dockerignore),
# so inside an image the `FROM` tag is the only thing selecting a toolchain.
# That exclusion exists because rustup does not normalise a partial version
# onto an installed patch release: with the toml present, a `1.97` pin against
# a base image shipping `1.97.1` made rustup sync a second 1.5G toolchain in
# every uncacheable stage. The cost of dropping it is that the two pins are no
# longer linked by anything but this check.
#
# When this fails, move both: bump `channel` in rust-toolchain.toml and the
# `FROM rust:<ver>` tags together.
set -euo pipefail

channel=$(
    awk -F'"' '/^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' rust-toolchain.toml
)

if [ -z "$channel" ]; then
    echo "ERROR: could not read [toolchain] channel from rust-toolchain.toml" >&2
    exit 1
fi

# git ls-files, so scratch Dockerfiles in an untracked worktree never count.
# The tag may carry a variant suffix (-trixie, -slim-trixie), hence the split
# on the first '-'; a bare `rust:1.97` has no suffix and works the same way.
offenders=$(
    git ls-files -- '*Dockerfile' '*Dockerfile.*' \
        | xargs -r grep -Hn '^FROM rust:' \
        | awk -F: -v want="$channel" '
            {
                tag = $4
                sub(/ .*$/, "", tag)      # drop " AS <stage>"
                split(tag, parts, "-")
                if (parts[1] != want) printf "  %s:%s  FROM rust:%s\n", $1, $2, tag
            }
        '
)

if [ -n "$offenders" ]; then
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error::Dockerfile Rust version does not match rust-toolchain.toml (${channel})"
    fi
    echo "ERROR: rust-toolchain.toml pins channel \"${channel}\", but these disagree:" >&2
    echo "$offenders" >&2
    exit 1
fi
