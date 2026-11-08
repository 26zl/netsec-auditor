# syntax=docker/dockerfile:1

# Build in a separate stage so build tools never reach the final image.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Compiler for dependencies without a prebuilt wheel on this architecture.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libffi-dev \
 && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /usr/local/bin/uv

WORKDIR /src
COPY . .
# Install the exact, hash-checked dependency versions from uv.lock, then the project.
RUN uv export --frozen --no-emit-project --format requirements.txt -o /tmp/requirements.txt \
 && pip install --prefix=/install --require-hashes -r /tmp/requirements.txt \
 && pip install --prefix=/install --no-deps .

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# nmap is the scan engine; ca-certificates covers the NVD, EPSS, KEV and Shodan lookups.
# PDF output is omitted to keep the image small; it needs libpango-1.0-0
# libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 and the [pdf] extra.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r auditor \
 && useradd -r -g auditor -s /usr/sbin/nologin -m auditor

COPY --from=builder /install /usr/local

USER auditor
WORKDIR /home/auditor

ENTRYPOINT ["netsec-auditor"]
CMD ["--help"]
