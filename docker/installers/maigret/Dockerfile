FROM python:3.13-slim

ARG MAIGRET_VERSION=0.6.6
RUN pip install --no-cache-dir "maigret==${MAIGRET_VERSION}" \
    && useradd --create-home --uid 1000 scanner

USER scanner
ENTRYPOINT ["maigret"]
