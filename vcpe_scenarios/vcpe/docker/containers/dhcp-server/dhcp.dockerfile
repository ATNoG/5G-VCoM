FROM alpine

RUN apk add --update nano dhcp \
    && rm -rf /var/cache/apk/*

RUN ["touch", "/var/lib/dhcp/dhcpd.leases"]

EXPOSE 67/udp 67/tcp

COPY	isc-dhcp-server	/etc/default/
COPY	dhcpd.conf /etc/dhcp
COPY	script.sh /

#ENTRYPOINT ["/script.sh"]

CMD	sh script.sh && tail -F /dev/null

#CMD	/usr/sbin/dhcpd -4 -f -d --no-pid -cf /etc/dhcp/dhcpd.conf && tail -F /dev/null

