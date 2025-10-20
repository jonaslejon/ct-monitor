# Secure Attestations Setup

This document explains how to set up secure attestations for the CT Monitor Docker images.

## What are Secure Attestations?

Secure attestations provide cryptographic proof of:
- **SBOM (Software Bill of Materials)**: Complete inventory of all software components
- **Provenance**: How the image was built, including source code and build environment
- **Integrity**: Verification that the image hasn't been tampered with

## Setup Requirements

### 1. Docker Hub Secrets

Add these secrets to your GitHub repository settings:

- `DOCKERHUB_USERNAME`: Your Docker Hub username
- `DOCKERHUB_TOKEN`: Your Docker Hub access token (with write permissions)

### 2. Local Build (Optional)

For local development with attestations:

```bash
# Make the build script executable
chmod +x build-with-attestations.sh

# Build with attestations (loads locally)
./build-with-attestations.sh

# Build and push directly to Docker Hub
./build-with-attestations.sh --push
```

**Note**: Without the `--push` flag, images are loaded locally. With `--push`, images are pushed directly to Docker Hub.

## GitHub Actions Workflow

The `.github/workflows/docker-attestations.yml` workflow will automatically:

1. Build multi-architecture images (amd64 + arm64)
2. Generate SBOM and provenance attestations
3. Push to Docker Hub with version tags
4. Enable vulnerability scanning

## Verification

### Verify Attestations

```bash
# Inspect image attestations
docker buildx imagetools inspect jonaslejon/ct-monitor:latest-attested

# Check SBOM
docker sbom jonaslejon/ct-monitor:latest-attested
```

### Verify Image Integrity

```bash
# Verify image signature (if using cosign)
docker verify jonaslejon/ct-monitor:latest-attested
```

## Benefits

- **Supply Chain Security**: Know exactly what's in your container
- **Audit Trail**: Cryptographic proof of build process
- **Compliance**: Meets security standards like SLSA Level 2
- **Trust**: Users can verify image authenticity

## Next Steps

1. Set up Docker Hub secrets in GitHub
2. Tag a release (e.g., `git tag v1.2.0 && git push origin v1.2.0`)
3. The workflow will automatically build and push with attestations

## References

- [Docker Buildx Attestations](https://docs.docker.com/build/attestations/)
- [SLSA Framework](https://slsa.dev/)
- [SBOM Standards](https://ntia.gov/page/software-bill-materials)