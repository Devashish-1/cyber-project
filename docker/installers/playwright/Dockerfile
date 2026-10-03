FROM mcr.microsoft.com/playwright@sha256:b022639ae9197f864040f92eef7b57c6d4b47db2190f77c909d8a5d902dd4b7e

ARG PLAYWRIGHT_VERSION=1.63.0

USER root
RUN npm install --global "playwright@${PLAYWRIGHT_VERSION}" \
    && mkdir -p /work \
    && chown pwuser:pwuser /work

USER pwuser
WORKDIR /work
ENTRYPOINT ["playwright"]
