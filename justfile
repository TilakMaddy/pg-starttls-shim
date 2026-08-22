# Publishing a release is exactly one thing: pushing a v* git tag.
# .github/workflows/release.yml does the rest -- it is the only thing that
# pushes to ghcr.io, and it only fires on a tag ref.
#
# Nothing is checked before the tag goes out, here or in CI. The image build is
# the only gate: if the code does not compile, the build fails and nothing is
# published -- but the tag and the release commit are already on origin.

default:
    @just --list

# Cut a release: x.Y.0 -- new behaviour.
publish-minor: (_publish "minor")

# Cut a release: x.y.Z -- fixes only.
publish-patch: (_publish "patch")

[private]
_publish bump:
    #!/usr/bin/env bash
    set -euo pipefail

    branch="$(git branch --show-current)"
    if [ "$branch" != "main" ]; then
        echo "refusing: releases are cut from main, you are on '$branch'" >&2
        exit 1
    fi
    if [ -n "$(git status --porcelain)" ]; then
        echo "refusing: working tree is dirty -- commit or stash first" >&2
        exit 1
    fi

    # A tag that is not on origin's main would publish an image nobody can
    # trace back to a reviewed commit.
    git fetch --quiet origin main
    if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
        echo "refusing: local main and origin/main have diverged -- pull/push first" >&2
        exit 1
    fi

    current="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/^version = "(.*)"$/\1/')"
    IFS=. read -r major minor patch <<< "$current"
    case "{{bump}}" in
        minor) next="$major.$((minor + 1)).0" ;;
        patch) next="$major.$minor.$((patch + 1))" ;;
    esac

    IFS=. read -r next_major next_minor _ <<< "$next"

    if git rev-parse -q --verify "refs/tags/v$next" >/dev/null; then
        echo "refusing: tag v$next already exists" >&2
        exit 1
    fi

    echo "release: $current -> $next  (tag v$next)"

    read -r -p "push v$next and publish ghcr.io/tilakmaddy/pg-starttls-shim:$next? [y/N] " reply
    [ "$reply" = "y" ] || [ "$reply" = "Y" ] || { echo "aborted"; exit 1; }

    awk -v v="$next" '/^version = "/ && !done {print "version = \"" v "\""; done=1; next} {print}' \
        Cargo.toml > Cargo.toml.tmp
    # Never let a truncated rewrite reach Cargo.toml.
    if ! grep -qx "version = \"$next\"" Cargo.toml.tmp; then
        rm -f Cargo.toml.tmp
        echo "refusing: failed to rewrite version in Cargo.toml, nothing changed" >&2
        exit 1
    fi
    mv Cargo.toml.tmp Cargo.toml
    # Refresh the version entry in Cargo.lock so the image's `--locked` build
    # does not fail on a stale lockfile.
    cargo check --quiet
    git add Cargo.toml Cargo.lock
    git commit -m "chore: release v$next"
    git tag -a "v$next" -m "v$next"
    git push origin main
    git push origin "v$next"

    echo
    echo "pushed v$next. CI is building linux/amd64 + linux/arm64 (the emulated"
    echo "arm64 leg takes ~10-20 min) and will publish these tags:"
    echo "  ghcr.io/tilakmaddy/pg-starttls-shim:$next"
    echo "  ghcr.io/tilakmaddy/pg-starttls-shim:$next_major.$next_minor"
    echo "  ghcr.io/tilakmaddy/pg-starttls-shim:latest"
    echo
    echo "watch it:  gh run watch \$(gh run list --limit 1 --json databaseId -q '.[0].databaseId')"
