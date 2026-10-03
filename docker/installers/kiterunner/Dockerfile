FROM alpine:3.22

ARG KITERUNNER_VERSION=1.0.2
ARG KITERUNNER_SHA256=6f0b70aabf747de592445a690281897eebbc45927e9264185d34ffb11637613b

RUN apk add --no-cache ca-certificates curl tar \
    && curl -fsSL "https://github.com/assetnote/kiterunner/releases/download/v${KITERUNNER_VERSION}/kiterunner_${KITERUNNER_VERSION}_linux_amd64.tar.gz" -o /tmp/kiterunner.tar.gz \
    && echo "${KITERUNNER_SHA256}  /tmp/kiterunner.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/kiterunner.tar.gz -C /usr/local/bin \
    && chmod 0755 /usr/local/bin/kr \
    && rm /tmp/kiterunner.tar.gz \
    && adduser -D -u 1000 scanner

USER scanner
ENTRYPOINT ["kr"]
