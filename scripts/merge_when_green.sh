#!/usr/bin/env bash
# Dispatches CI on BRANCH, waits for that run, and squash-merges the branch's
# pull request only if CI passed. Used by the Upgrade rPGP and Release
# workflows on the pull requests they open (README, "Upgrading rPGP").
#
# Pull requests opened with GITHUB_TOKEN do not trigger CI, so it is
# dispatched here; its checks appear on the pull request. Needs gh with
# GH_TOKEN (actions: write, contents: write, pull-requests: write) and
# GH_REPO.
#
# Usage: scripts/merge_when_green.sh BRANCH
set -euo pipefail

branch=${1:?usage: scripts/merge_when_green.sh BRANCH}

gh workflow run ci.yml --ref "$branch"

# The dispatch returns no run id: the branch is new, so the only
# workflow_dispatch run of CI on it is this one.
run=""
for _ in $(seq 1 36); do
  sleep 5
  run=$(gh run list --workflow ci.yml --branch "$branch" --event workflow_dispatch \
    --limit 1 --json databaseId --jq '.[0].databaseId // empty')
  if [ -n "$run" ]; then
    break
  fi
done
if [ -z "$run" ]; then
  echo "No CI run found on $branch: not merging." >&2
  exit 1
fi

echo "Waiting for CI run $run on $branch."
if ! gh run watch "$run" --exit-status --interval 30 > /dev/null; then
  echo "CI failed on $branch (run $run): not merging." >&2
  exit 1
fi

gh pr merge "$branch" --squash --delete-branch
echo "Merged $branch."
