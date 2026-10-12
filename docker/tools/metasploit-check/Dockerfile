FROM metasploitframework/metasploit-framework@sha256:a05bb5cac4c4d95b2ebeb972813ce17b2da022d7647c4f17e9537bffa2906ed6

USER root
RUN set -eux; \
    setcap -r /usr/local/bin/ruby; \
    addgroup -g 65532 msfcheck; \
    adduser -D -u 65532 -G msfcheck -h /home/msfcheck msfcheck; \
    install -d -o 65532 -g 65532 -m 0700 /home/msfcheck/.msf4

ENV HOME=/home/msfcheck
WORKDIR /usr/src/metasploit-framework
USER 65532:65532
ENTRYPOINT ["/usr/src/metasploit-framework/msfconsole"]
CMD ["-q", "-x", "version; exit -y"]
