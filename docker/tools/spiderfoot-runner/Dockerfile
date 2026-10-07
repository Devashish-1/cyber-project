FROM security-platform/spiderfoot:4.0

USER root
COPY --chown=root:root effective_tld_names.dat /opt/spiderfoot/effective_tld_names.dat
RUN sed -i \
      -e "s/'verify': True/'verify': False/" \
      -e "s/'fetchcerts': True/'fetchcerts': False/" \
      /opt/spiderfoot/modules/sfp_crt.py \
    && sed -i \
      "s#'_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat'#'_internettlds': '@/opt/spiderfoot/effective_tld_names.dat'#" \
      /opt/spiderfoot/sf.py \
    && grep -q "'verify': False" /opt/spiderfoot/modules/sfp_crt.py \
    && grep -q "'fetchcerts': False" /opt/spiderfoot/modules/sfp_crt.py \
    && grep -q "@/opt/spiderfoot/effective_tld_names.dat" /opt/spiderfoot/sf.py \
    && echo "ba7d836c0ea57a8bcf9f1fcb868066a7554bed029b441ecc6204ad8494a32612  /opt/spiderfoot/effective_tld_names.dat" | sha256sum -c -
USER spiderfoot

LABEL org.opencontainers.image.title="Security Platform SpiderFoot runner" \
      org.opencontainers.image.description="SpiderFoot 4.0 with DNS verification and certificate fetching disabled for the fixed crt.sh adapter" \
      security-platform.base-image="sha256:db52a3e00f05a9701a12e3c727511c1191a23dd72a70d2164fc01e13ea4ca8c7" \
      security-platform.public-suffix-list-sha256="ba7d836c0ea57a8bcf9f1fcb868066a7554bed029b441ecc6204ad8494a32612"
