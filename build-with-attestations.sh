#!/bin/bash
# Build script for CT Monitor with secure attestations

set -e

# Get version from the Python file
VERSION=$(python3 -c "import re; print(re.search(r\"__version__ = ['\\\"]([^'\\\"]+)['\\\"]\", open('ct-monitor.py').read()).group(1))")

# Check if --push flag was provided
OUTPUT_FLAG="--load"
if [[ "$1" == "--push" ]]; then
  OUTPUT_FLAG="--push"
  echo "Building and pushing CT Monitor v$VERSION with secure attestations..."
else
  echo "Building CT Monitor v$VERSION with secure attestations (local only)..."
  echo "Add --push flag to push directly to Docker Hub"
  echo ""
fi

# Build with SBOM and provenance
docker buildx build \
  --platform linux/amd64 \
  --sbom=true \
  --provenance=mode=min \
  -t jonaslejon/ct-monitor:$VERSION-attested \
  -t jonaslejon/ct-monitor:latest-attested \
  $OUTPUT_FLAG \
  .

echo ""
echo "✅ Build completed with attestations"
echo "Image tags:"
echo "  - jonaslejon/ct-monitor:$VERSION-attested"
echo "  - jonaslejon/ct-monitor:latest-attested"
echo ""

if [[ "$OUTPUT_FLAG" == "--push" ]]; then
  echo "Images have been pushed to Docker Hub"
  echo ""
  echo "To inspect attestations, run:"
  echo "  docker buildx imagetools inspect jonaslejon/ct-monitor:$VERSION-attested"
else
  echo "Images are loaded locally. To push to Docker Hub, run:"
  echo "  docker push jonaslejon/ct-monitor:$VERSION-attested"
  echo "  docker push jonaslejon/ct-monitor:latest-attested"
  echo ""
  echo "Or rebuild with push flag:"
  echo "  ./build-with-attestations.sh --push"
fi