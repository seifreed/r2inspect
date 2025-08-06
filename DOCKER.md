# Docker Support for r2inspect

Complete Docker support for running r2inspect in isolated, secure containers with a single unified Dockerfile supporting both development and production builds.

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Production mode (default)
docker-compose up -d
docker-compose run r2inspect malware.exe

# Development mode
docker-compose --profile dev up -d
docker-compose run r2inspect-dev  # Interactive shell

# Stop services
docker-compose down
```

### Using Make

```bash
# Production build and usage
make build          # Build production image
make run FILE=malware.exe  # Analyze a file
make batch          # Batch analysis
make shell          # Interactive shell

# Development build and usage
make build-dev      # Build development image
make shell-dev      # Development shell with mounted source
```

### Using Shell Scripts

#### Unix/Linux/macOS

```bash
# Make script executable
chmod +x docker-run.sh

# Analyze a file
./docker-run.sh malware.exe

# Batch analysis
./docker-run.sh --batch ./samples

# Interactive shell
./docker-run.sh --shell
```

#### Windows

```cmd
# Analyze a file
docker-run.bat malware.exe

# Batch analysis
docker-run.bat --batch .\samples

# Interactive shell
docker-run.bat --shell
```

## Unified Docker Image

The project uses a single `Dockerfile` that supports both production and development builds via build arguments:

### Production Build (Default)
- **Build args**: `BUILD_TYPE=production`
- **Size**: ~500MB
- **Features**: Minimal dependencies, security hardened, optimized for analysis
- **Install**: Standard pip install

```bash
# Build production image
docker build --build-arg BUILD_TYPE=production -t r2inspect:latest .
# Or use Make
make build
```

### Development Build
- **Build args**: `BUILD_TYPE=development`
- **Size**: ~800MB
- **Features**: Development tools (vim, gdb, ipython, pytest, jupyter), editable install
- **Install**: Editable pip install with dev dependencies

```bash
# Build development image
docker build --build-arg BUILD_TYPE=development -t r2inspect:dev .
# Or use Make
make build-dev
```

### Key Differences

| Feature | Production | Development |
|---------|------------|-------------|
| Python packages | Core only | Core + dev tools |
| System packages | Minimal | Extended (vim, gdb, etc.) |
| Install type | `pip install .` | `pip install -e .` |
| Default shell | r2inspect command | Interactive bash |
| Debugging tools | No | Yes (gdb, strace, etc.) |
| Jupyter support | No | Yes (port 8888) |

## Directory Structure

The Docker setup expects the following directory structure:

```
r2inspect/
├── samples/      # Malware samples to analyze (read-only mount)
├── output/       # Analysis results (read-write mount)
├── config/       # Configuration and YARA rules (read-only mount)
└── ...
```

Create directories:
```bash
make dirs
# Or manually
mkdir -p samples output config
```

## Security Features

### Container Security
- Runs as non-root user (`analyst`)
- Dropped capabilities (only SYS_PTRACE and DAC_READ_SEARCH retained)
- No new privileges flag set
- Read-only root filesystem (where possible)
- Memory and CPU limits enforced

### Resource Limits
- **Memory**: 2GB (configurable)
- **CPU**: 2 cores (configurable)
- **Temp Storage**: 512MB (tmpfs)

### Network Isolation
- Custom bridge network
- No internet access by default
- Isolated from host network

## Environment Variables

Configure behavior using environment variables:

```bash
# Set custom directories
export SAMPLES_DIR=/path/to/samples
export OUTPUT_DIR=/path/to/output
export CONFIG_DIR=/path/to/config

# Run with custom settings
./docker-run.sh malware.exe
```

### Available Variables
- `SAMPLES_DIR`: Directory containing samples (default: `./samples`)
- `OUTPUT_DIR`: Directory for output files (default: `./output`)
- `CONFIG_DIR`: Directory for configuration (default: `./config`)
- `R2_MAXCORES`: Maximum CPU cores for r2 (default: 4)
- `R2_MAXMEM`: Maximum memory for r2 (default: 2048M)

## Advanced Usage

### Custom YARA Rules

Place custom YARA rules in the `config/` directory:

```bash
# Copy YARA rules
cp custom_rules.yar config/

# Run with custom rules
docker run -v ./config:/home/analyst/config:ro r2inspect:latest \
    --yara /home/analyst/config malware.exe
```

### Batch Processing

```bash
# Using docker-compose
docker-compose run r2inspect --batch /home/analyst/samples \
    --threads 10 -o /home/analyst/output/results.csv

# Using Make
make batch ARGS="--threads 10"

# Using script
./docker-run.sh --batch ./samples
```

### Interactive Analysis

Start an interactive shell for manual analysis:

```bash
# Using Make
make shell

# Using script
./docker-run.sh --shell

# Then inside container
r2inspect /home/analyst/samples/malware.exe
r2 /home/analyst/samples/malware.exe
```

### Volume Mounts

Custom volume mounts for specific use cases:

```bash
# Mount specific file for analysis
docker run -v /path/to/file.exe:/tmp/analysis.exe:ro \
    r2inspect:latest /tmp/analysis.exe

# Mount entire malware repository
docker run -v /malware/repo:/data:ro \
    r2inspect:latest --batch /data
```

## Building and Publishing

### Build Image

```bash
# Standard build
docker build -t r2inspect:latest .

# Build with BuildKit (faster)
DOCKER_BUILDKIT=1 docker build -t r2inspect:latest .

# Build without cache
docker build --no-cache -t r2inspect:latest .
```

### Tag and Push to Registry

```bash
# Tag image
docker tag r2inspect:latest your-registry/r2inspect:latest

# Push to registry
docker push your-registry/r2inspect:latest

# Or using Make
make push REGISTRY=your-registry REGISTRY_USER=your-username
```

## Troubleshooting

### Permission Issues

If you encounter permission issues with output files:

```bash
# Fix ownership of output directory
sudo chown -R $(id -u):$(id -g) output/
```

### Memory Issues

If analysis fails due to memory limits:

```bash
# Increase memory limit
docker run --memory=4g --memory-swap=4g r2inspect:latest malware.exe

# Or modify docker-compose.yml
services:
  r2inspect:
    deploy:
      resources:
        limits:
          memory: 4G
```

### Build Failures

If the build fails:

```bash
# Clean Docker cache
docker system prune -a

# Build with verbose output
docker build --progress=plain -t r2inspect:latest .
```

### Container Debugging

Debug issues inside the container:

```bash
# Run with debug shell
docker run -it --entrypoint /bin/bash r2inspect:latest

# Check radare2 installation
r2 -v

# Test r2pipe
python -c "import r2pipe; r2 = r2pipe.open(); print(r2.cmd('?V'))"
```

## Performance Optimization

### Build Cache

Use BuildKit for faster builds:

```bash
# Enable BuildKit
export DOCKER_BUILDKIT=1

# Build with inline cache
docker build --build-arg BUILDKIT_INLINE_CACHE=1 -t r2inspect:latest .
```

### Layer Caching

Optimize Dockerfile for better caching:
- Requirements changes less frequently → copy first
- Application code changes frequently → copy last

### Multi-Platform Builds

Build for multiple architectures:

```bash
# Setup buildx
docker buildx create --use

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 \
    -t r2inspect:latest --push .
```

## Health Monitoring

The container includes health checks:

```bash
# Check container health
docker ps --format "table {{.Names}}\t{{.Status}}"

# View health check logs
docker inspect r2inspect --format='{{json .State.Health}}'
```

## Cleanup

Remove Docker resources:

```bash
# Using Make
make clean

# Manually
docker stop r2inspect-analysis
docker rm r2inspect-analysis
docker rmi r2inspect:latest

# Remove all r2inspect images
docker images | grep r2inspect | awk '{print $3}' | xargs docker rmi

# Clean everything
docker system prune -a
```

## Support

For issues or questions about Docker support:
1. Check container logs: `docker logs r2inspect-analysis`
2. Verify radare2 installation: `docker run r2inspect:latest r2 -v`
3. Test r2pipe: `docker run r2inspect:latest python -c "import r2pipe"`
4. Open an issue on GitHub with Docker logs and error messages
