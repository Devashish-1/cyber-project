FROM python:3.13-slim

ARG SHERLOCK_VERSION=0.16.2
RUN pip install --no-cache-dir "sherlock-project==${SHERLOCK_VERSION}" \
    && useradd --create-home --uid 1000 scanner

USER scanner
ENTRYPOINT ["sherlock"]
