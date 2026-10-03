FROM alpine:3.22

ARG FFUF_VERSION=2.3.0
ARG FFUF_SHA256=b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb

RUN apk add --no-cache ca-certificates curl tar \
    && curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz \
    && echo "${FFUF_SHA256}  /tmp/ffuf.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
    && rm /tmp/ffuf.tar.gz \
    && adduser -D -u 1000 scanner

USER scanner
ENTRYPOINT ["ffuf"]
