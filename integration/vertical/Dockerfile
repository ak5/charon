FROM docker.io/library/alpine@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

RUN apk add --no-cache \
    ca-certificates=20260611-r0 \
    curl=8.20.0-r0 \
    github-cli=2.83.0-r6
RUN adduser -D -u 10001 workload

COPY run-in-workload.sh /usr/local/bin/run-in-workload
USER workload
ENTRYPOINT ["/usr/local/bin/run-in-workload"]
