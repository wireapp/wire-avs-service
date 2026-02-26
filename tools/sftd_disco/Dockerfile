FROM alpine:3.23.3

RUN apk add --no-cache curl bash openssl bind-tools jq
COPY sftd_disco.sh /usr/bin/sftd_disco.sh

USER nobody
ENTRYPOINT ["/usr/bin/sftd_disco.sh"]
