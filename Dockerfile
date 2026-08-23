FROM docker.io/library/rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.source="https://github.com/ak5/charon"
COPY --from=build /src/target/release/charon /usr/local/bin/charon
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/charon"]
CMD ["--config", "/etc/charon/charon.toml"]
