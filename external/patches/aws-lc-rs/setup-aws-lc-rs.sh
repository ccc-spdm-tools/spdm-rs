#!/bin/bash
# Setup script for aws-lc-rs submodule on Windows and Linux.
#
# aws-lc-rs has a nested submodule (aws-lc-sys/aws-lc) and uses symlinks
# (aws-lc-sys/builder -> ../builder). On Windows, git symlinks may not
# resolve properly, so we replace them with copies or junctions.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AWS_LC_RS_DIR="$(cd "$SCRIPT_DIR/../../aws-lc-rs" && pwd)"

echo "Setting up aws-lc-rs at: $AWS_LC_RS_DIR"

# Step 1: Initialize the nested aws-lc submodule
pushd "$AWS_LC_RS_DIR" > /dev/null
if [ ! -f "aws-lc-sys/aws-lc/CMakeLists.txt" ]; then
    echo "Initializing aws-lc-sys/aws-lc submodule..."
    git submodule update --init --depth 1 aws-lc-sys/aws-lc
fi
popd > /dev/null

# Step 2: Fix symlinks on Windows
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
