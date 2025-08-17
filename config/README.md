# Configuration Directory

This directory is used for storing custom configuration files when running r2inspect in Docker containers.

## Usage

Place your custom files here:
- Custom YARA rules (`.yar` or `.yara` files)
- Configuration overrides (`config.json`)

## Docker

When using Docker, this directory is mounted as `/home/analyst/config` inside the container.

Example:
```bash
# Place custom YARA rules
cp my_rules.yar config/

# Run with Docker
make shell
# or
docker-compose up
```

The container will have read-only access to files in this directory.