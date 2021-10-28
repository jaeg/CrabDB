FROM scratch
ARG binary
ARG version
ENV version=$version
ADD bin/$binary /app

ENTRYPOINT ["/app"]