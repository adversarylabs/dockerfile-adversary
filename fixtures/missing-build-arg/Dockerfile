FROM alpine:3.20@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
ARG BUILD_VERSION
RUN printf '%s' "$BUILD_VERSION" > /version

FROM scratch AS runtime
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
USER 65532
