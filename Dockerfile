ARG BASE_IMAGE=python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a
ARG RADARE2_VERSION=6.1.8
ARG RADARE2_COMMIT=d904d02e1157b45135c6e61651d890bac8abe873
ARG SOURCE_DATE_EPOCH=1782215316

FROM ${BASE_IMAGE} AS builder

# Package versions are fixed by the immutable Debian snapshot above.
# hadolint ignore=DL3008
RUN sed -i \
        -e 's|http://deb.debian.org/debian$|http://snapshot.debian.org/archive/debian/20260803T000000Z|' \
        -e 's|http://deb.debian.org/debian-security$|http://snapshot.debian.org/archive/debian-security/20260803T000000Z|' \
        -e '/Signed-By:/a Check-Valid-Until: no' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        libfuzzy-dev \
        libmagic-dev \
        libssl-dev \
        pkg-config \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

ARG RADARE2_VERSION
ARG RADARE2_COMMIT
ARG SOURCE_DATE_EPOCH

WORKDIR /tmp/radare2
RUN git init \
    && git remote add origin https://github.com/radareorg/radare2.git \
    && git fetch --depth 1 origin "refs/tags/${RADARE2_VERSION}:refs/tags/${RADARE2_VERSION}" \
    && git checkout --detach "${RADARE2_VERSION}" \
    && test "$(git rev-parse HEAD)" = "${RADARE2_COMMIT}" \
    && ./configure --prefix=/opt/radare2 --with-rpath \
    && make -j"$(nproc)" \
    && make install

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /src
COPY pyproject.toml requirements-docker.lock README.md LICENSE MANIFEST.in setup.py ./
COPY r2inspect/ r2inspect/
RUN pip install --no-cache-dir --require-hashes -r requirements-docker.lock \
    && pip install --no-cache-dir --no-deps .

FROM ${BASE_IMAGE} AS runtime

# Package versions are fixed by the immutable Debian snapshot above.
# hadolint ignore=DL3008
RUN sed -i \
        -e 's|http://deb.debian.org/debian$|http://snapshot.debian.org/archive/debian/20260803T000000Z|' \
        -e 's|http://deb.debian.org/debian-security$|http://snapshot.debian.org/archive/debian-security/20260803T000000Z|' \
        -e '/Signed-By:/a Check-Valid-Until: no' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        file \
        libfuzzy2 \
        libmagic1 \
        ssdeep \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin analyst \
    && mkdir -p /samples /output /workspace \
    && chown -R analyst:analyst /samples /output /workspace

COPY --from=builder /opt/radare2/ /usr/local/
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:/usr/local/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/lib" \
    PYTHONUNBUFFERED=1 \
    R2_NOPLUGINS=1 \
    R2PIPE_SPAWN=1 \
    RADARE2_RCFILE=""

WORKDIR /workspace
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import subprocess, r2pipe; subprocess.run(['r2', '-v'], check=True, stdout=subprocess.DEVNULL)"]

ENTRYPOINT ["r2inspect"]
CMD ["--help"]
