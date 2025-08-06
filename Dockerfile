# Unified Dockerfile for r2inspect malware analysis tool
# Supports both development and production builds via build args

# Build arguments
ARG BUILD_TYPE=production
ARG BASE_IMAGE=python:3.11-slim
ARG RADARE2_VERSION=master

# Multi-stage build
FROM ${BASE_IMAGE} AS base

# Build argument available in all stages
ARG BUILD_TYPE
ARG RADARE2_VERSION

# Install system dependencies based on build type
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core dependencies (always needed)
    gcc \
    g++ \
    make \
    git \
    wget \
    curl \
    pkg-config \
    libssl-dev \
    libmagic-dev \
    file \
    patch \
    libfuzzy-dev \
    python3-dev \
    ssdeep \
    # Development tools (only for dev builds)
    $(if [ "$BUILD_TYPE" = "development" ]; then echo "\
        vim \
        nano \
        less \
        gdb \
        strace \
        ltrace \
        procps \
        net-tools \
        iputils-ping \
        tree \
        htop"; fi) \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 using proper make install method
RUN echo "Installing radare2 (${RADARE2_VERSION})..." && \
    git clone --depth 1 --branch ${RADARE2_VERSION} https://github.com/radareorg/radare2.git /tmp/radare2 && \
    cd /tmp/radare2 && \
    # Configure and build radare2 properly
    ./configure --prefix=/usr/local --with-rpath && \
    make -j$(nproc) && \
    make install && \
    # Update library path
    echo "/usr/local/lib" > /etc/ld.so.conf.d/radare2.conf && \
    ldconfig && \
    # Create additional symlinks for broader accessibility
    ln -sf /usr/local/bin/r2 /usr/bin/r2 && \
    ln -sf /usr/local/bin/radare2 /usr/bin/radare2 && \
    ln -sf /usr/local/bin/r2 /bin/r2 && \
    ln -sf /usr/local/bin/radare2 /bin/radare2 && \
    # Clean up source
    rm -rf /tmp/radare2 && \
    # Verify installation works
    echo "=== Radare2 Installation Verification ===" && \
    r2 -version && \
    which r2 && \
    ls -la /usr/local/bin/r2*

# Note: TLSH will be installed via Python package (python-tlsh)

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python packages based on build type
COPY requirements-docker.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements-docker.txt && \
    # Try to install optional packages (may fail, that's OK)
    pip install --no-cache-dir python-tlsh>=4.5.0 || echo "python-tlsh installation failed, will use fallback" && \
    pip install --no-cache-dir ssdeep>=3.4 || echo "ssdeep installation failed, will use system binary" && \
    # Development packages (only for dev builds)
    if [ "$BUILD_TYPE" = "development" ]; then \
        pip install --no-cache-dir \
            ipython \
            ipdb \
            pytest \
            pytest-cov \
            black \
            ruff \
            bandit \
            mypy \
            pre-commit \
            jupyterlab; \
    fi

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash analyst && \
    mkdir -p /app /samples /output /config /workspace && \
    chown -R analyst:analyst /app /samples /output /config /workspace

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=analyst:analyst . /app/

# Install r2inspect package
# Use editable install for development, regular install for production
RUN if [ "$BUILD_TYPE" = "development" ]; then \
        pip install -e .; \
    else \
        pip install .; \
    fi

# Switch to non-root user
USER analyst

# Create user directories
RUN mkdir -p /home/analyst/{samples,output,config,workspace,.r2}

# Set environment variables for radare2 and r2pipe
ENV PYTHONUNBUFFERED=1
ENV R2_NOPLUGINS=1
ENV R2PIPE_SPAWN=1
ENV PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
ENV LD_LIBRARY_PATH="/usr/local/lib:/usr/lib"
ENV R2_HOME="/usr/local"
ENV RADARE2_RCFILE=""

# Development-specific environment
RUN if [ "$BUILD_TYPE" = "development" ]; then \
        echo 'export PYTHONDONTWRITEBYTECODE=1' >> /home/analyst/.bashrc && \
        echo 'export PS1="[r2inspect-dev] \u@\h:\w$ "' >> /home/analyst/.bashrc && \
        echo 'alias ll="ls -la"' >> /home/analyst/.bashrc && \
        echo 'alias r2="r2 -A"' >> /home/analyst/.bashrc; \
    fi && \
    # Add radare2 environment to bashrc for all builds
    echo 'export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"' >> /home/analyst/.bashrc && \
    echo 'export LD_LIBRARY_PATH="/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH"' >> /home/analyst/.bashrc && \
    echo 'export R2_HOME="/usr/local"' >> /home/analyst/.bashrc && \
    echo 'export RADARE2_RCFILE=""' >> /home/analyst/.bashrc

# Expose port for development web interface (if needed in future)
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD r2 -v && python -c "import r2pipe; print('OK')" || exit 1

# Set entrypoint and command based on build type
RUN if [ "$BUILD_TYPE" = "development" ]; then \
        echo '#!/bin/bash\nexport PATH="/usr/local/bin:/usr/bin:/bin:$PATH"\nexport LD_LIBRARY_PATH="/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH"\nexport R2_HOME="/usr/local"\nexport RADARE2_RCFILE=""\nif [ "$#" -eq 0 ]; then exec /bin/bash; else exec r2inspect "$@"; fi' > /home/analyst/entrypoint.sh; \
    else \
        echo '#!/bin/bash\nexport PATH="/usr/local/bin:/usr/bin:/bin:$PATH"\nexport LD_LIBRARY_PATH="/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH"\nexport R2_HOME="/usr/local"\nexport RADARE2_RCFILE=""\nexec r2inspect "$@"' > /home/analyst/entrypoint.sh; \
    fi && \
    chmod +x /home/analyst/entrypoint.sh

ENTRYPOINT ["/home/analyst/entrypoint.sh"]
CMD ["--help"]