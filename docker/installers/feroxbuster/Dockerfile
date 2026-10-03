FROM alpine:3.22

ARG FEROX_VERSION=2.13.1
ARG FEROX_SHA256=7985c00e6803b0f25d5e9139f7472279f3f4d891429627a5cedc629e53992d80

RUN apk add --no-cache ca-certificates curl tar \
    && curl -fsSL "https://github.com/epi052/feroxbuster/releases/download/v${FEROX_VERSION}/x86_64-linux-feroxbuster.tar.gz" -o /tmp/feroxbuster.tar.gz \
    && echo "${FEROX_SHA256}  /tmp/feroxbuster.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/feroxbuster.tar.gz -C /usr/local/bin feroxbuster \
    && rm /tmp/feroxbuster.tar.gz \
    && adduser -D -u 1000 scanner

USER scanner
ENTRYPOINT ["feroxbuster"]
