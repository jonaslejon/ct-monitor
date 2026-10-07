#!/bin/bash
# Build script for CT Monitor with secure attestations

set -e

# Get version from the Python file
VERSION=$(python3 -c "import re; print(re.search(r\"__version__ = ['\\\"]([^'\\\"]+)['\\\"]\", open('ct-monitor.py').read()).group(1))")
REVISION=$(git rev-parse HEAD 2>/dev/null || echo unknown)
IMAGE=jonaslejon/ct-monitor

# Check if --push flag was provided
if [[ "$1" == "--push" ]]; then
  # A pushed image must match a commit, so its revision label means something
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "Refusing to push: commit your changes first" >&2
    exit 1
  fi
  # A release is multi-arch and moves every tag: version, major.minor, latest and the -attested aliases
  OUTPUT_FLAGS=(--push --platform linux/amd64,linux/arm64)
  TAGS=(-t $IMAGE:$VERSION -t $IMAGE:${VERSION%.*} -t $IMAGE:latest -t $IMAGE:$VERSION-attested -t $IMAGE:latest-attested)
  echo "Building and pushing CT Monitor v$VERSION ($REVISION) with secure attestations..."
else
  # Docker's classic image store cannot load a multi-arch image, so a local build is for this machine only
  OUTPUT_FLAGS=(--load)
  TAGS=(-t $IMAGE:$VERSION-attested -t $IMAGE:latest-attested)
  echo "Building CT Monitor v$VERSION with secure attestations (local only)..."
  echo "Add --push flag to push directly to Docker Hub"
  echo ""
fi

# Build with SBOM and provenance
docker buildx build \
  --sbom=true \
  --provenance=mode=max \
  --label org.opencontainers.image.version=$VERSION \
  --label org.opencontainers.image.revision=$REVISION \
  "${TAGS[@]}" \
  "${OUTPUT_FLAGS[@]}" \
  .

echo ""
echo "✅ Build completed with attestations"
echo "Image tags:"
for t in "${TAGS[@]}"; do [[ "$t" != "-t" ]] && echo "  - $t"; done
echo ""

if [[ "$1" == "--push" ]]; then
  echo "Images have been pushed to Docker Hub"
  echo ""
  echo "To inspect attestations, run:"
  echo "  docker buildx imagetools inspect $IMAGE:$VERSION"
else
  echo "Images are loaded locally. To build for amd64 + arm64 and push to Docker Hub, run:"
  echo "  ./build-with-attestations.sh --push"
fi
