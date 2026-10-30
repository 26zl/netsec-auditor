# syntax=docker/dockerfile:1

# Resolve and install the project + its dependencies into an isolated prefix.
# Kept in a separate stage so build tools never reach the final image.
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Compiler + headers as a safety net for any dependency without a prebuilt
# wheel on the target arch (amd64/arm64). Most deps ship wheels, so this is
# rarely used, and it is discarded with this stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libffi-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN pip install --prefix=/install .

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# nmap: required at runtime — port scanning wraps the nmap binary via
#       python-nmap.
# ca-certificates: HTTPS for CVE / EPSS / Shodan lookups.
# PDF reports (WeasyPrint) need Pango/Cairo system libs; they are intentionally
# omitted to keep the image small — the tool degrades to JSON/HTML reports. Add
# libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 if you need PDF output.
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
