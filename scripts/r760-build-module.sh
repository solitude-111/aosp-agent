#!/bin/bash
# android_module_build validation stage for the r760 testbed.
# Invoked by engine.verify() with cwd = the agent's migration worktree.
#
# Chain (see docs/retropatch-adaptation-delivery.md §r760 for the host fixes
# this encodes: short OUT_DIR, giant-command script patch, python2 shim,
# portable JDK11):
#   1. candidate patch = <cwd>/../backport.patch (engine exports before verify)
#   2. `m nothing` forces kati/soong regeneration so NEW source files in the
#      candidate enter the build graph
#   3. patch-giants.py rewrites any >128KB command lines (kernel single-arg
#      limit) into script files -- regeneration restores them, so re-patch
#      every time
#   4. direct ninja builds services + FrameworksUiServicesTests (bypasses
#      soong_ui, which would regenerate and drop the patches again)
#   5. artifacts are copied back into <cwd>/out-artifacts/ for engine hashing
#   6. our private tree copy is restored to pristine and verified clean
set -o pipefail

WORKTREE="$(pwd)"
# The engine's worktree is <run_dir>/<cve>/<repository> (repository may be
# nested, e.g. frameworks/base), so the run directory is TWO levels up from
# the worktree root.
RUN_DIR="$(cd "$WORKTREE/../.." && pwd)"
PATCH="$RUN_DIR/backport.patch"
TARGET=cebf5c06997b64f4e47a1611edb5f97044509d76
BASE=/data/junjie/aosp/out/retropatch-r760
TREE="$BASE/tree"
FB="$TREE/frameworks/base"
OUT="$BASE/rp-out"

[ -f "$PATCH" ] || { echo "candidate patch not found: $PATCH" >&2; exit 121; }
[ -d "$FB" ] || { echo "private tree copy missing: $FB" >&2; exit 122; }

cd "$FB"
if [ -n "$(git status --porcelain)" ]; then
  echo "private tree dirty at entry; refusing to build" >&2
  git status --porcelain >&2
  exit 120
fi

git apply --binary "$PATCH" || {
  echo "candidate patch does not apply to the private tree copy" >&2
  git checkout -- . 2>/dev/null
  exit 118
}

export PATH="$BASE/jdk/jdk-11.0.32.1+1/bin:$BASE/scratch/bin:$PATH"
export OUT_DIR="$OUT"
export TMPDIR="$BASE/scratch/tmp"
export XDG_CACHE_HOME="$BASE/scratch/cache"
export ANDROID_PREFS_ROOT="$BASE/scratch/cache/android"
export GRADLE_USER_HOME="$BASE/scratch/cache/gradle"
export GOCACHE="$BASE/scratch/cache/go"
export JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$TMPDIR"
mkdir -p "$TMPDIR" "$WORKTREE/out-artifacts"

cd "$TREE"
# Regenerate the graph so the candidate's new files are globbed in, then
# re-patch over-limit commands, then build with plain ninja.
( source build/envsetup.sh && lunch sdk_phone_x86_64-userdebug >/dev/null 2>&1 && \
  m nothing >/dev/null 2>&1 ) || echo "WARN: graph regeneration step failed; continuing with existing graph" >&2
python3 "$BASE/patch-giants.py" >/dev/null 2>&1 || echo "WARN: giant-command patcher failed" >&2

./prebuilts/build-tools/linux-x86/bin/ninja -j32 \
  -f "$OUT/combined-sdk_phone_x86_64.ninja" services FrameworksUiServicesTests
build_rc=$?

for artifact in services.jar FrameworksUiServicesTests.apk; do
  found="$(find "$OUT/target/product" -name "$artifact" 2>/dev/null | head -1)"
  if [ -n "$found" ]; then
    cp "$found" "$WORKTREE/out-artifacts/$artifact"
  fi
done

# Always restore our disposable copy, even after a failed build.
cd "$FB"
git checkout -- .
git clean -fdq
[ -z "$(git status --porcelain)" ] || { echo "restore failed; tree copy left dirty" >&2; exit 119; }

exit "$build_rc"
