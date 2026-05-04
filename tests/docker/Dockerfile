# Pinned to a specific Alpine patch release so that base-image rebuilds cannot
# silently bump net-snmp and invalidate the captured fixtures in
# `tests/fixtures/`. When intentionally bumping this pin, re-capture both
# `netsnmp_v1_trap.b64` and `netsnmp_v2c_trap.b64` from the new net-snmp version
# and confirm the golden-bytes tests still pass.
FROM alpine:3.23.4

RUN apk add --no-cache net-snmp net-snmp-tools \
 && mkdir -p /var/log/snmp

COPY snmptrapd.conf /etc/snmp/snmptrapd.conf

EXPOSE 162/udp

ENTRYPOINT ["snmptrapd", "-f", "-Lf", "/var/log/snmp/trap.log", \
            "-c", "/etc/snmp/snmptrapd.conf", "--disableAuthorization=yes", \
            "udp:0.0.0.0:162"]
