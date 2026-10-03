FROM ubuntu:24.04

ARG CODEQL_VERSION=2.27.1

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
      "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
      -o /tmp/codeql.zip \
    && unzip -q /tmp/codeql.zip -d /opt \
    && rm /tmp/codeql.zip \
    && git clone --depth 1 --branch "codeql-cli/v${CODEQL_VERSION}" \
      https://github.com/github/codeql.git /opt/codeql-repo

RUN groupadd --system scanner \
    && useradd --system --gid scanner --home-dir /work --create-home scanner \
    && chown -R scanner:scanner /work

ENV PATH="/opt/codeql:${PATH}" \
    CODEQL_SEARCH_PATH="/opt/codeql-repo"
WORKDIR /work
USER scanner
ENTRYPOINT ["codeql"]
CMD ["--help"]
