# Multi-architecture Dockerfile for r2inspect
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/.local/bin:${PATH}"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Basic tools
    curl \
    wget \
    git \
    build-essential \
    # Python and pip
    python3 \
    python3-pip \
    python3-dev \
    # Required for radare2
    pkg-config \
    libssl-dev \
    # Required for python-magic
    libmagic1 \
    libmagic-dev \
    # Required for ssdeep
    libfuzzy-dev \
    libfuzzy2 \
    ssdeep \
    # Required for CFFI
    libffi-dev \
    # Required for pyimpfuzzy
    automake \
    libtool \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 from official repository
RUN git clone --depth 1 https://github.com/radareorg/radare2 \
    && cd radare2 \
    && ./sys/install.sh \
    && cd .. \
    && rm -rf radare2

# Create app directory
WORKDIR /app

# Upgrade pip and install build tools
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel

# Install pefile first (required by pyimpfuzzy)
RUN pip3 install --no-cache-dir pefile>=2023.2.7

# Clone and install pyimpfuzzy from source (version 0.5)
RUN cd /tmp && \
    git clone https://github.com/JPCERTCC/impfuzzy.git && \
    cd impfuzzy/pyimpfuzzy && \
    python3 setup.py build && \
    python3 setup.py install && \
    cd / && \
    rm -rf /tmp/impfuzzy

# Copy requirements
COPY requirements.txt .

# Install dependencies for ssdeep first
RUN pip3 install --no-cache-dir pycparser cffi

# Install Python dependencies
RUN pip3 install --no-cache-dir \
    r2pipe>=1.8.0 \
    colorama>=0.4.6 \
    tabulate>=0.9.0 \
    pyfiglet>=0.8.post1 \
    python-magic>=0.4.27 \
    yara-python>=4.3.1 \
    pandas>=2.1.0 \
    rich>=13.7.0 \
    click>=8.1.7 \
    cryptography>=41.0.7 \
    requests>=2.31.0 \
    prettytable>=3.9.0 \
    ssdeep>=3.4 \
    py-tlsh>=4.7.0 \
    telfhash>=0.9.8 \
    psutil \
    pybloom-live \
    simhash

# Copy the entire project
COPY . .

# Install r2inspect
RUN pip3 install --no-cache-dir -e .

# Create directories for analysis
RUN mkdir -p /samples /output /app/logs

# Create entrypoint script
RUN echo '#!/bin/bash\n\
if [ "$#" -eq 0 ]; then\n\
    echo "r2inspect Docker Container"\n\
    echo "Usage:"\n\
    echo "  docker run -v /path/to/samples:/samples r2inspect <file>"\n\
    echo "  docker run -v /path/to/samples:/samples r2inspect -j /samples/malware.exe"\n\
    echo "  docker run -v /path/to/samples:/samples -v /path/to/output:/output r2inspect --batch /samples -c -o /output"\n\
    exit 1\n\
fi\n\
exec r2inspect "$@"' > /entrypoint.sh && chmod +x /entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command (show help)
CMD []