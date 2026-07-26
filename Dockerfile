FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/charon /usr/local/bin/charon
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/charon"]
CMD ["--config", "/etc/charon/charon.toml"]

