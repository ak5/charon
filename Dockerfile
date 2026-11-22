FROM docker.io/library/rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release \
    && mkdir /runtime-libs \
    && cp /usr/lib/*/libssl.so.3 /usr/lib/*/libcrypto.so.3 /runtime-libs/

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.source="https://github.com/ak5/charon"
COPY --from=build /src/target/release/charon /usr/local/bin/charon
COPY --from=build /runtime-libs/ /usr/lib/
COPY --from=build /usr/share/doc/libssl3/copyright /usr/share/doc/libssl3/copyright
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/charon/THIRD_PARTY_NOTICES.md
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/charon"]
CMD ["--config", "/etc/charon/charon.toml"]
