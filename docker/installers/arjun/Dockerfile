FROM python:3.13-slim

ARG ARJUN_VERSION=2.2.7

RUN pip install --no-cache-dir "arjun==${ARJUN_VERSION}" \
    && useradd --create-home --uid 1000 scanner

USER scanner
ENTRYPOINT ["arjun"]
