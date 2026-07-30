FROM alpine:3.20
COPY id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa && rm -f /root/.ssh/id_rsa
CMD ["/bin/sh"]
