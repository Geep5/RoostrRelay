# Default: pure-Odin storage and BIP-340. VERIFY_DUAL adds a test oracle for soak deployments.
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates xz-utils clang llvm \
    && rm -rf /var/lib/apt/lists/*

# Odin compiler (pinned release)
ARG ODIN_VERSION=dev-2026-08
RUN curl -fsSL "https://github.com/odin-lang/Odin/releases/download/${ODIN_VERSION}/odin-linux-amd64-${ODIN_VERSION}.tar.gz" \
    | tar -xz -C /opt && mv /opt/odin-linux-amd64-* /opt/odin
ENV PATH="/opt/odin:${PATH}"

ARG VERIFY_DUAL=false
# Only the explicitly selected soak image needs the C reference verifier.
RUN if [ "$VERIFY_DUAL" = true ]; then \
    apt-get update && apt-get install -y --no-install-recommends make git autoconf automake libtool \
    && git clone --depth 1 --branch v0.6.0 https://github.com/bitcoin-core/secp256k1 /tmp/secp \
    && cd /tmp/secp && ./autogen.sh \
    && ./configure --enable-module-schnorrsig --disable-shared --disable-tests --disable-benchmark --prefix=/usr/local \
    && make -j"$(nproc)" && make install; fi

COPY src /build/src
RUN cd /build && odin build src -out:roostr-relay -o:speed \
    -define:VERIFY_DUAL=${VERIFY_DUAL} -extra-linker-flags:"-L/usr/local/lib"

# Runtime retains the OS C runtime; neither default application subsystem uses a C library.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/roostr-relay /app/roostr-relay
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 7777
CMD ["/app/entrypoint.sh"]
