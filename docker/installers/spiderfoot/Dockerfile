FROM python:3.9-slim-bookworm

ARG SPIDERFOOT_TAG=v4.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential cargo git libffi-dev libjpeg-dev libssl-dev \
       libxml2-dev libxslt1-dev libopenjp2-7-dev swig zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${SPIDERFOOT_TAG}" \
      https://github.com/smicallef/spiderfoot.git /opt/spiderfoot \
    && printf 'Cython<3\n' > /tmp/constraint.txt \
    && PIP_CONSTRAINT=/tmp/constraint.txt pip install --no-cache-dir 'Cython<3' wheel \
    && PIP_CONSTRAINT=/tmp/constraint.txt pip install --no-cache-dir -r /opt/spiderfoot/requirements.txt \
    && rm -f /tmp/constraint.txt

RUN groupadd --system spiderfoot \
    && useradd --system --gid spiderfoot --home-dir /var/lib/spiderfoot spiderfoot \
    && install -d -o spiderfoot -g spiderfoot /var/lib/spiderfoot/log /var/lib/spiderfoot/cache

WORKDIR /opt/spiderfoot
ENV SPIDERFOOT_DATA=/var/lib/spiderfoot \
    SPIDERFOOT_LOGS=/var/lib/spiderfoot/log \
    SPIDERFOOT_CACHE=/var/lib/spiderfoot/cache
USER spiderfoot
EXPOSE 5001
ENTRYPOINT ["python"]
CMD ["sf.py", "-l", "0.0.0.0:5001"]
