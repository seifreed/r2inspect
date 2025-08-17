# Samples Directory

This directory is used for storing malware samples to analyze when running r2inspect in Docker containers.

## Usage

Place your samples here for batch analysis:
```bash
# Copy samples
cp malware.exe samples/

# Run batch analysis with Docker
make batch

# Or analyze specific file
make run FILE=samples/malware.exe
```

## Security

⚠️ **WARNING**: This directory may contain malware samples.
- Always handle files in this directory with extreme caution
- Use isolated environments for analysis
- Do not execute files directly

## Docker

When using Docker, this directory is mounted as `/home/analyst/samples` inside the container with read-only access.

## .gitignore

Sample files should never be committed to the repository. Common malware extensions are already in `.gitignore`.