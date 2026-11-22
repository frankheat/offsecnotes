#!/bin/sh
# Mirror the `public` branch into the web root. Run by offsecnotes-sync.service.
set -eu

REPO=https://github.com/frankheat/offsecnotes.git
export GIT_DIR=/var/lib/offsecnotes/site.git
[ -d "$GIT_DIR" ] || git init -q --bare "$GIT_DIR"
git config core.symlinks false # symlinks become plain files: can't point Apache outside the web root
export GIT_WORK_TREE=/var/www/offsecnotes

git fetch -q --depth 1 "$REPO" public
git reset -q --hard FETCH_HEAD
git clean -qfdx
