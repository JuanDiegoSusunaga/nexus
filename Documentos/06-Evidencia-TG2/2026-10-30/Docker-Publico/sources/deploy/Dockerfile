# Las imágenes base quedan fijadas por contenido, sin usar la etiqueta latest.
ARG RUST_IMAGE=rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
FROM ${RUST_IMAGE} AS verified
WORKDIR /src/nexus
ENV CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2
COPY . .
RUN cargo fetch --locked
RUN cargo check --workspace --all-targets --locked --offline
RUN cargo test --workspace --locked --offline
RUN cargo build --release -p nexus-cli --locked --offline

FROM ${RUNTIME_IMAGE} AS runtime
RUN groupadd --gid 10001 nexus \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin nexus \
    && mkdir -p /var/lib/nexus /etc/nexus \
    && chown 10001:10001 /var/lib/nexus
COPY --from=verified /src/nexus/target/release/nexus /usr/local/bin/nexus
USER 10001:10001
WORKDIR /var/lib/nexus
EXPOSE 19001/tcp
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/nexus"]
CMD ["testnet", "--help"]
