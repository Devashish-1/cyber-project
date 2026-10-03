FROM alpine:3.22

ARG RUSTSCAN_VERSION=2.4.1
ARG RUSTSCAN_SHA256=f3a4365d939e3b81f25ba8c37852ce9ac9e938c3cc882c5b3e6fff6152c740be

RUN apk add --no-cache ca-certificates curl nmap tar unzip \
    && curl -fsSL "https://github.com/bee-san/RustScan/releases/download/${RUSTSCAN_VERSION}/x86_64-linux-rustscan.tar.gz.zip" -o /tmp/rustscan.zip \
    && echo "${RUSTSCAN_SHA256}  /tmp/rustscan.zip" | sha256sum -c - \
    && unzip -q /tmp/rustscan.zip -d /tmp/rustscan-release \
    && tar -xzf /tmp/rustscan-release/x86_64-linux-rustscan.tar.gz -C /usr/local/bin \
    && chmod 0755 /usr/local/bin/rustscan \
    && rm -rf /tmp/rustscan.zip /tmp/rustscan-release \
    && adduser -D -u 1000 scanner

USER scanner
ENTRYPOINT ["rustscan"]
