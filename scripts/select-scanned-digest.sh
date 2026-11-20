#!/usr/bin/env bash
# Prints the digest that build-scan scanned for one image, for the publish
# job of .github/workflows/multi-arch.yml.
#
# Usage: scripts/select-scanned-digest.sh DIR IMAGE EXPECTED_IMAGES
#
# DIR holds the downloaded artifacts, one directory per artifact:
# DIR/digest-<image>-<attempt>/digest. Each build-scan leg names its artifact
# with the run attempt, so a run holds one artifact per image and attempt:
# a full "Re-run all jobs" adds a new set next to the earlier attempt's, and
# a rerun of only the failed jobs adds artifacts for the legs it reruns and
# keeps the others. For each image the artifact of the highest attempt is the
# one its newest passing build-scan leg wrote, so that is the one read.
#
# Fails, printing nothing on stdout, when a directory name does not have that
# shape, when the number of distinct images is not EXPECTED_IMAGES (the two
# matrices of the workflow list the images separately), when IMAGE has no
# artifact, or when its newest artifact does not hold a sha256 digest. The
# newest artifact is never skipped for an older one.
set -euo pipefail

[ "$#" -eq 3 ] || { echo "usage: $0 DIR IMAGE EXPECTED_IMAGES" >&2; exit 2; }
dir=$1 img=$2 expected=$3
[[ "$expected" =~ ^[0-9]+$ ]] || { echo "::error::expected image count '$expected' is not a number" >&2; exit 2; }
[ -d "$dir" ] || { echo "::error::no digest artifacts were downloaded (no $dir)" >&2; exit 1; }

images=()
best=""
best_attempt=0
while IFS= read -r -d '' path; do
  name=${path##*/}
  [[ "$name" =~ ^digest-([a-z0-9][a-z0-9._-]*)-([1-9][0-9]*)$ ]] \
    || { echo "::error::artifact $name is not digest-<image>-<attempt>" >&2; ls "$dir" >&2; exit 1; }
  image=${BASH_REMATCH[1]} attempt=${BASH_REMATCH[2]}
  seen=false
  for i in "${images[@]+"${images[@]}"}"; do [ "$i" = "$image" ] && seen=true; done
  $seen || images+=("$image")
  if [ "$image" = "$img" ] && [ "$attempt" -gt "$best_attempt" ]; then
    best_attempt=$attempt best=$path
  fi
done < <(find "$dir" -mindepth 1 -maxdepth 1 -type d -name 'digest-*' -print0)

count=${#images[@]}
[ "$count" -eq "$expected" ] \
  || { echo "::error::build-scan handed over $count digests (${images[*]-}), publish has $expected images" >&2; ls "$dir" >&2; exit 1; }
[ -n "$best" ] || { echo "::error::no scanned digest for $img (expected $dir/digest-$img-<attempt>/digest)" >&2; exit 1; }

f="$best/digest"
[ -f "$f" ] || { echo "::error::no scanned digest for $img in attempt $best_attempt (expected $f)" >&2; exit 1; }
digest=$(tr -d '[:space:]' < "$f")
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || { echo "::error::$f holds '$digest', not a sha256 digest" >&2; exit 1; }
echo "$img: attempt $best_attempt of ${count} images" >&2
printf '%s\n' "$digest"
