#!/usr/bin/env bash
# User-manual donor history deepening. The agent NEVER runs this script:
# it performs a network fetch, which is reserved for the human operator
# (AGENTS.md red line 1 / adaptation plan P2.1).
#
# Usage:
#   bash scripts/deepen_donor.sh <donor-git/frameworks-base.git> <remote-url> <target_commit>
# Example:
#   bash scripts/deepen_donor.sh /home/guolei/aosp-agent-48550/donor-git/frameworks-base.git \
#       https://android.googlesource.com/platform/frameworks/base \
#       cebf5c06997b64f4e47a1611edb5f97044509d76
#
# TODO(user): confirm the remote branch name for your donor snapshot (e.g.
# android16-release, main). It is NOT guessed here; export BRANCH=<name> to
# override the default.
set -euo pipefail

DONOR="${1:?usage: deepen_donor.sh <donor .git> <remote-url> <target_commit>}"
REMOTE="${2:?missing remote url}"
TARGET="${3:?missing target commit}"
BRANCH="${BRANCH:-main}"

if [ ! -d "$DONOR" ]; then
    echo "donor git dir not found: $DONOR" >&2
    exit 1
fi

git --git-dir="$DONOR" remote add origin "$REMOTE" 2>/dev/null || true

# frameworks/base full history is ~1-2 GB. --shallow-since pulls only the
# range needed to cover target..source_parent (the Android 12 baseline was
# cut 2021-08-24), avoids --unshallow's full-history cost, and does not
# error when the store is already sufficiently deep.
git --git-dir="$DONOR" fetch --shallow-since=2021-08-24 origin "$BRANCH"

git --git-dir="$DONOR" remote remove origin

echo "Verification: the target..HEAD range now has history for case files."
echo "Run for the 48550 case file:"
echo "  git --git-dir=$DONOR log --oneline $TARGET..5f0874dde8c0572e078ebb9d74d8f891e3103175^ -- services/core/java/com/android/server/slice/SlicePermissionManager.java"
