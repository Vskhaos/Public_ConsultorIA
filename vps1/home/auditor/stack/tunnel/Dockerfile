FROM alpine:3.20
RUN apk add --no-cache openssh-client autossh && \
    adduser -D -u 1500 tunnel && \
    mkdir -p /home/tunnel/.ssh && chown -R tunnel:tunnel /home/tunnel
COPY entrypoint.sh /entrypoint.sh
USER tunnel
ENV AUTOSSH_GATETIME=0
ENTRYPOINT ["/entrypoint.sh"]
