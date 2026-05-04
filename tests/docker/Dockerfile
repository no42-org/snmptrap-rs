FROM alpine:3.21

RUN apk add --no-cache net-snmp net-snmp-tools \
 && mkdir -p /var/log/snmp

COPY snmptrapd.conf /etc/snmp/snmptrapd.conf

EXPOSE 162/udp

ENTRYPOINT ["snmptrapd", "-f", "-Lf", "/var/log/snmp/trap.log", \
            "-c", "/etc/snmp/snmptrapd.conf", "--disableAuthorization=yes", \
            "udp:0.0.0.0:162"]
