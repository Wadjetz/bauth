#!/bin/bash
# Bumps the version shared by the server and the SDK, the way a release needs it (README
# "Releasing"): ./bump_version.sh patch|minor|major
# Merging the bump into main releases it: release.yml pushes the image and publishes the SDK.
set -euo pipefail

cd "$(dirname "$0")"

PACKAGE=bauth_sdk/package.json

part=${1:-}
case "$part" in
patch | minor | major) ;;
*)
  echo "usage: $0 patch|minor|major" >&2
  exit 1
  ;;
esac

current=$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)
if [[ ! $current =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "Cannot read the version of Cargo.toml: '$current'" >&2
  exit 1
fi
major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}
patch=${BASH_REMATCH[3]}

# The release refuses a mismatch: so does the bump, rather than spreading one.
version=$(node -p "require('./$PACKAGE').version")
if [ "$version" != "$current" ]; then
  echo "Cargo.toml is $current but $PACKAGE is $version: fix it first" >&2
  exit 1
fi

case "$part" in
patch) next="$major.$minor.$((patch + 1))" ;;
minor) next="$major.$((minor + 1)).0" ;;
major) next="$((major + 1)).0.0" ;;
esac

# Only the version line of [workspace.package]: the members take theirs with version.workspace.
perl -pi -e "\$in = /^\[workspace\.package\]/ if /^\[/; s/^version = \"\Q$current\E\"/version = \"$next\"/ if \$in" Cargo.toml
(cd bauth_sdk && npm version "$next" --no-git-tag-version --silent >/dev/null)

# Cargo.lock records the members' versions; openapi.json carries the server's (`info.version`),
# and the SDK types are generated from it.
cargo update --workspace --quiet
UPDATE_OPENAPI=1 SQLX_OFFLINE=true cargo test --quiet -p bauth_server openapi >/dev/null
(cd bauth_sdk && npm run --silent generate >/dev/null && npm test --silent >/dev/null)

echo "$current -> $next"
git status --short -- Cargo.toml Cargo.lock bauth_server/openapi.json bauth_sdk
