FROM debian:bookworm-slim AS build

ARG MASSDNS_VERSION=v1.1.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates git \
    && git clone --depth 1 --branch "${MASSDNS_VERSION}" https://github.com/blechschmidt/massdns.git /src \
    && make -C /src

FROM debian:bookworm-slim
RUN useradd --create-home --uid 1000 scanner
COPY --from=build /src/bin/massdns /usr/local/bin/massdns
USER scanner
ENTRYPOINT ["massdns"]
