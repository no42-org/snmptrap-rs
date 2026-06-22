# Pinned to a specific Alpine patch release so that base-image rebuilds cannot
# silently shift the snmptrapd version that integration tests parse log output
# from. The captured fixtures in `tests/fixtures/` are sender-side Net-SNMP
# `snmptrap` outputs and are independent of this image — bump freely; only
# re-capture if a future workflow generates fresh fixtures from the container's
# `snmptrap` binary.
FROM alpine:3.24.1

RUN apk add --no-cache net-snmp net-snmp-tools \
 && mkdir -p /var/log/snmp

COPY snmptrapd.conf /etc/snmp/snmptrapd.conf

EXPOSE 162/udp

ENTRYPOINT ["snmptrapd", "-f", "-Lf", "/var/log/snmp/trap.log", \
            "-c", "/etc/snmp/snmptrapd.conf", "--disableAuthorization=yes", \
            "-On", \
            "udp:0.0.0.0:162"]
