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

Until these are set, the workflow fails at the Docker Hub login, so releases are pushed with the build
script below.

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

**Note**: Without the `--push` flag, the image is built for this machine's platform and loaded locally,
tagged `-attested` only. With `--push`, it is built for amd64 and arm64 and pushed with every release tag:
`<version>`, `<major.minor>`, `latest`, `<version>-attested` and `latest-attested`. A push refuses to run
with uncommitted changes, so the image's `org.opencontainers.image.revision` label names its commit.

## GitHub Actions Workflow

The `.github/workflows/docker-attestations.yml` workflow will automatically:

1. Build multi-architecture images (amd64 + arm64, arm64 under QEMU)
2. Generate SBOM and provenance attestations
3. Push to Docker Hub with the same tags as the build script, plus `sha-<commit>`

## Verification

### Verify Attestations

```bash
# Inspect image attestations
docker buildx imagetools inspect jonaslejon/ct-monitor:latest

# Show the provenance and the SBOM
docker buildx imagetools inspect jonaslejon/ct-monitor:latest --format '{{ json .Provenance }}'
docker buildx imagetools inspect jonaslejon/ct-monitor:latest --format '{{ json .SBOM }}'
```

The images are not signed (no cosign signature), so there is no signature to verify yet.

## Benefits

- **Supply Chain Security**: Know exactly what's in your container
- **Audit Trail**: Cryptographic proof of build process
- **Compliance**: Meets security standards like SLSA Level 2
- **Trust**: Users can verify image authenticity

## Next Steps

1. Set up Docker Hub secrets in GitHub
2. Tag a release (e.g., `git tag v1.4.1 && git push origin v1.4.1`)
3. The workflow will automatically build and push with attestations

## References

- [Docker Buildx Attestations](https://docs.docker.com/build/attestations/)
- [SLSA Framework](https://slsa.dev/)
- [SBOM Standards](https://ntia.gov/page/software-bill-materials)