#!/bin/bash
# r2inspect Docker wrapper script

# Detect the current directory
CURRENT_DIR=$(pwd)

# Create directories if they don't exist
mkdir -p "$CURRENT_DIR/samples" "$CURRENT_DIR/output"

# Check if image exists, build if not
if [[ "$(docker images -q r2inspect:latest 2> /dev/null)" == "" ]]; then
    echo "Building r2inspect Docker image..."
    docker build -t r2inspect:latest "$(dirname "$0")"
fi

# Run r2inspect with mounted volumes
docker run --rm \
    -v "$CURRENT_DIR/samples:/samples" \
    -v "$CURRENT_DIR/output:/output" \
    -v "$CURRENT_DIR:/current" \
    r2inspect "$@"