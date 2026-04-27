FROM zeek/zeek:6.0

RUN groupadd -g 1000 zeekuser \
 && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin zeekuser \
 && mkdir -p /logs /scripts \
 && chown -R 1000:1000 /logs /scripts

USER 1000:1000
WORKDIR /logs
