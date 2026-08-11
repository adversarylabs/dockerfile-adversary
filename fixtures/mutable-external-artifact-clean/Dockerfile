FROM alpine:3.20@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN wget -nv https://repo1.maven.org/maven2/org/example/library/3.3.4/library-3.3.4.jar -O /opt/library.jar
RUN curl -fL https://example.test/tool.tar.gz -o /tmp/tool.tar.gz && echo "$TOOL_SHA256  /tmp/tool.tar.gz" | sha256sum -c -
RUN curl -fL https://github.com/example/tool/releases/download/v1.8.2/tool -o /usr/local/bin/tool
USER 1000
