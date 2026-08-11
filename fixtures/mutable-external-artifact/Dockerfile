FROM alpine:3.20@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN wget -nv https://storage.example/hadoop/gcs-connector-hadoop2-latest.jar -O /opt/gcs.jar
RUN curl -fL https://example.test/tool/releases/latest/download/tool -o /usr/local/bin/tool
RUN curl -fL https://downloads.example.test/helper.tar.gz -o /tmp/helper.tar.gz
RUN curl -fL https://downloads.example.test/unchecked.sh -o /tmp/unchecked.sh && sha256sum /tmp/unchecked.sh
USER 1000
