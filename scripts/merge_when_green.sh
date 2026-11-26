#!/usr/bin/env bash
# Dispatches CI on BRANCH, whose head must be SHA, waits for that run, and
# squash-merges the branch's pull request only if CI passed, and only at
# SHA (a push to the branch meanwhile makes the merge fail). If CI fails,
# the pull request goes back to draft and the script fails. Used by the
# Upgrade rPGP and Release workflows (README, "Upgrading rPGP").
#
# Pull requests opened with GITHUB_TOKEN do not trigger CI, so it is
# dispatched here; its checks appear on the pull request. Needs gh with
# GH_TOKEN (actions: write, contents: write, pull-requests: write) and
# GH_REPO.
#
# Usage: scripts/merge_when_green.sh BRANCH SHA
set -euo pipefail

branch=${1:?usage: scripts/merge_when_green.sh BRANCH SHA}
sha=${2:?usage: scripts/merge_when_green.sh BRANCH SHA}

runs() {
  gh run list --workflow ci.yml --event workflow_dispatch --branch "$branch" --limit 50 \
    --json databaseId,headSha --jq ".[] | select(.headSha == \"$sha\") | .databaseId"
}

# The dispatch returns no run id: the new run is the one on SHA that was not
# there before (no clock comparison, no "latest").
before=$(runs)
gh workflow run ci.yml --ref "$branch"
run=""
for _ in $(seq 1 60); do
  sleep 5
  for id in $(runs); do
    if ! grep -qxF "$id" <<< "$before"; then
      run=$id
      break
    fi
  done
  if [ -n "$run" ]; then
    break
  fi
done
if [ -z "$run" ]; then
  echo "No CI run found on $branch at $sha: not merging." >&2
  exit 1
fi

echo "Waiting for CI run $run on $branch ($sha)."
if ! gh run watch "$run" --exit-status --interval 30 > /dev/null; then
  echo "CI failed on $branch (run $run): not merging; the pull request is a draft again." >&2
  gh pr ready "$branch" --undo || true
  exit 1
fi

gh pr merge "$branch" --squash --delete-branch --match-head-commit "$sha"
echo "Merged $branch at $sha."
