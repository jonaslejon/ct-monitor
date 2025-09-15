#!/bin/bash
# Build script for CT Monitor with secure attestations

set -e

# Get version from the Python file
VERSION=$(python -c "import re; print(re.search(r\"__version__ = ['\"]([^'\"]+)['\"]\", open('ct-monitor.py').read()).group(1))")

# Build with attestations
echo "Building CT Monitor v$VERSION with secure attestations..."

# Build with SBOM and provenance
docker buildx build \
  --platform linux/amd64 \
  --sbom=true \
  --provenance=mode=min \
  -t jonaslejon/ct-monitor:$VERSION-attested \
  -t jonaslejon/ct-monitor:latest-attested \
  .

echo ""
echo "✅ Build completed with attestations"
echo "Image tags:"
echo "  - jonaslejon/ct-monitor:$VERSION-attested"
echo "  - jonaslejon/ct-monitor:latest-attested"
echo ""
echo "To push to Docker Hub, run:"
echo "  docker push jonaslejon/ct-monitor:$VERSION-attested"
echo "  docker push jonaslejon/ct-monitor:latest-attested"
echo ""
echo "To inspect attestations, run:"
echo "  docker buildx imagetools inspect jonaslejon/ct-monitor:$VERSION-attested"