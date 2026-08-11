FROM alpine:3.20@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
ARG BUILD_VERSION
RUN printf '%s' "$BUILD_VERSION" > /version

FROM builder AS inherited
LABEL org.opencontainers.image.version="${BUILD_VERSION}"

FROM scratch AS runtime
ARG APP_VERSION
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.revision="${RELEASE_VERSION:-development}"
USER 65532
