FROM python:3.13-slim

ARG RECON_COMMIT=c08acee0f84645ecf521ec616ac2dde94cbc1d63
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git libxml2-dev libxslt1-dev gcc \
    && git clone https://github.com/lanmaster53/recon-ng.git /opt/recon-ng \
    && git -C /opt/recon-ng checkout "${RECON_COMMIT}" \
    && pip install --no-cache-dir -r /opt/recon-ng/REQUIREMENTS \
    && apt-get purge -y git gcc \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 scanner \
    && chown -R scanner:scanner /opt/recon-ng

USER scanner
WORKDIR /opt/recon-ng
ENTRYPOINT ["python", "recon-ng"]
