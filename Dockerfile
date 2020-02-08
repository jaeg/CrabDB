FROM scratch
ARG binary
ARG version
ENV version=$version
ADD pkg/$binary /app

ENTRYPOINT ["/app"]