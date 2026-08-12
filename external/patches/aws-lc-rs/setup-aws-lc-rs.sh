#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AWS_LC_RS_DIR="$(cd "$SCRIPT_DIR/../../aws-lc-rs" && pwd)"
AWS_LC_DIR="$AWS_LC_RS_DIR/aws-lc-sys/aws-lc"
AWS_LC_RS_BASE="9232f4df24627662243a1a7cf71d885b2ff6ce72"
AWS_LC_BASE="683ebde4bf3bcc016a9a710ad6b49c0c91b59161"
AWS_LC_RS_PATCH="$SCRIPT_DIR/0001-feat-aws-lc-rs-support-freestanding-algorithm-profil.patch"
AWS_LC_PATCH="$SCRIPT_DIR/aws-lc/0001-build-support-freestanding-algorithm-scoped-profiles.patch"

apply-patch() {
    local repository="$1"
    local patch="$2"

    if git -C "$repository" apply --unidiff-zero --reverse --check "$patch" 2>/dev/null; then
        echo "Already applied: $(basename "$patch")"
    elif git -C "$repository" apply --unidiff-zero --check "$patch"; then
        git -C "$repository" apply --unidiff-zero "$patch"
        echo "Applied: $(basename "$patch")"
    else
        echo "Cannot apply $(basename "$patch") in $repository" >&2
        echo "Reset the submodule to its pinned revision and retry." >&2
        exit 1
    fi
}

require-revision() {
    local repository="$1"
    local expected="$2"
    local actual

    actual="$(git -C "$repository" rev-parse HEAD)"
    if [[ "$actual" != "$expected" ]]; then
        echo "$repository is at $actual; expected $expected" >&2
        exit 1
    fi
}

echo "Setting up aws-lc-rs at: $AWS_LC_RS_DIR"

require-revision "$AWS_LC_RS_DIR" "$AWS_LC_RS_BASE"
git -C "$AWS_LC_RS_DIR" submodule update --init aws-lc-sys/aws-lc
require-revision "$AWS_LC_DIR" "$AWS_LC_BASE"

apply-patch "$AWS_LC_DIR" "$AWS_LC_PATCH"
apply-patch "$AWS_LC_RS_DIR" "$AWS_LC_RS_PATCH"

# aws-lc-sys/builder is a symlink to ../builder which may not resolve on Windows
BUILDER_LINK="$AWS_LC_RS_DIR/aws-lc-sys/builder"
BUILDER_TARGET="$AWS_LC_RS_DIR/builder"

if [ -f "$BUILDER_LINK" ] && [ ! -d "$BUILDER_LINK" ]; then
    echo "Fixing aws-lc-sys/builder symlink..."
    rm -f "$BUILDER_LINK"
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        # On Windows (Git Bash / MSYS2), use directory junction via cmd
        cmd //c "mklink /J \"$(cygpath -w "$BUILDER_LINK")\" \"$(cygpath -w "$BUILDER_TARGET")\""
    else
        # On Linux/macOS, recreate as proper symlink
        ln -s ../builder "$BUILDER_LINK"
    fi
elif [ ! -e "$BUILDER_LINK" ]; then
    echo "Creating aws-lc-sys/builder link..."
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        cmd //c "mklink /J \"$(cygpath -w "$BUILDER_LINK")\" \"$(cygpath -w "$BUILDER_TARGET")\""
    else
        ln -s ../builder "$BUILDER_LINK"
    fi
fi

echo "aws-lc-rs setup complete."
