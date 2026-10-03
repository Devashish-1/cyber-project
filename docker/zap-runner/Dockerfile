FROM ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef

USER root
RUN install -d -o 1000 -g 1000 -m 0700 /zap/output /zap/wrk
USER zap
WORKDIR /zap/output
