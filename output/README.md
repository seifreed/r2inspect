# Output Directory

This directory is used for storing analysis results when running r2inspect in Docker containers.

## Usage

Analysis results will be automatically saved here:
- JSON analysis reports
- CSV batch results
- Log files

## Docker

When using Docker, this directory is mounted as `/home/analyst/output` inside the container with read-write access.

Example:
```bash
# Run batch analysis
make batch

# Results will be saved to:
# output/batch_results.csv
```

## Local Usage

When running r2inspect locally (without Docker), you can specify any output directory:
```bash
r2inspect malware.exe -j -o /path/to/output.json
```

## Cleanup

This directory can be safely cleaned:
```bash
rm -rf output/*
```

Analysis results in this directory are excluded from version control.