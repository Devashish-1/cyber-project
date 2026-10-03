FROM python:3.13-slim

ARG DNSRECON_VERSION=1.6.3

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && git clone --depth 1 --branch "${DNSRECON_VERSION}" https://github.com/darkoperator/dnsrecon.git /src \
    && pip install --no-cache-dir /src \
    && rm -rf /src /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 scanner

USER scanner
ENTRYPOINT ["dnsrecon"]
