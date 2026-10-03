FROM kalilinux/kali-rolling

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       bloodhound.py certipy-ad netexec python3-impacket responder \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system auditor \
    && useradd --system --gid auditor --home-dir /work --create-home auditor

WORKDIR /work
USER auditor
CMD ["/bin/bash"]
