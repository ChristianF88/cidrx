# Releasing cidrx

## Quick Start

```bash
# Create and push a tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Done! Check https://github.com/ChristianF88/cidrx/releases
```

GitHub Actions automatically:
- ✅ Builds binaries for Linux (amd64, arm64, armv7), macOS (amd64, arm64), Windows (amd64)
- ✅ Runs tests and static analysis
- ✅ Creates GitHub Release with changelog
- ✅ Uploads binaries and checksums

**Build time:** ~3-5 minutes

---

## Configuration Files

- `.github/workflows/release.yml` - GitHub Actions workflow
- `cidrx/src/.goreleaser.yaml` - GoReleaser configuration
- `cidrx/src/version/version.go` - Version variables (injected by GoReleaser)

---

## Versioning

Follow [Semantic Versioning](https://semver.org/):

- **v1.0.0** - Production release
- **v1.0.0-beta.1** - Pre-release (automatically detected)
- **dev** - Development builds (no tag)

---

## Common Tasks

### Test Locally

```bash
# Install GoReleaser
go install github.com/goreleaser/goreleaser@latest

# Build without releasing
cd cidrx/src
goreleaser build --snapshot --clean

# Check binaries
ls -lh dist/
```

### Delete Wrong Tag

```bash
git tag -d v1.0.0                    # Delete locally
git push origin :refs/tags/v1.0.0   # Delete remotely
```

### Re-run Failed Build

1. Go to GitHub Actions tab
2. Click the failed workflow
3. Click "Re-run all jobs"

---

## What Gets Released

### Binaries
```
cidrx_v1.0.0_Linux_x86_64.tar.gz
cidrx_v1.0.0_Linux_arm64.tar.gz
cidrx_v1.0.0_Linux_armv7.tar.gz
cidrx_v1.0.0_Darwin_x86_64.tar.gz    # macOS Intel
cidrx_v1.0.0_Darwin_arm64.tar.gz     # macOS Apple Silicon
cidrx_v1.0.0_Windows_x86_64.zip
checksums.txt
```

Each archive includes: binary, README.md, LICENSE, cidrx.toml.example

### Version in Binary

```bash
./cidrx --version
# Output: cidrx version v1.0.0
```

---

## Advanced Customization

### Add Docker Images

Edit `cidrx/src/.goreleaser.yaml`:

```yaml
dockers:
  - image_templates:
      - "ghcr.io/christianf88/cidrx:{{ .Version }}"
      - "ghcr.io/christianf88/cidrx:latest"
    dockerfile: ../../Dockerfile
```

### Add Homebrew Tap

```yaml
brews:
  - name: cidrx
    repository:
      owner: ChristianF88
      name: homebrew-tap
    homepage: "https://github.com/ChristianF88/cidrx"
    description: "High-performance botnet detection tool"
```

---

## Troubleshooting

### Build Fails

**Check:**
- Tag format starts with `v` (e.g., `v1.0.0`)
- Tests passing: `go test ./...`
- Workflow has `contents: write` permission

### Binary Won't Run

**Verify:**
- Architecture matches: `uname -m`
- Static linking enabled: `CGO_ENABLED=0` in workflow
- File permissions: `chmod +x cidrx`

---

## Documentation

- GoReleaser: https://goreleaser.com
- GitHub Actions: https://docs.github.com/en/actions
- Semantic Versioning: https://semver.org
