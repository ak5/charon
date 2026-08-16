FROM docker.io/library/rust:1.97.1-bookworm@sha256:14bc9c5966e7b3a385794b3d5389a8765668342025fbcc7b2e3d2866ac4bd8c3 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77
LABEL org.opencontainers.image.source="https://github.com/ak5/charon"
COPY --from=build /src/target/release/charon /usr/local/bin/charon
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/charon"]
CMD ["--config", "/etc/charon/charon.toml"]
