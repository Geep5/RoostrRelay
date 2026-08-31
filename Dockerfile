# Builder: Odin release + static libsecp256k1 + static SQLite amalgamation.
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates xz-utils clang llvm make git autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/*

# Odin compiler (pinned release)
ARG ODIN_VERSION=dev-2026-08
RUN curl -fsSL "https://github.com/odin-lang/Odin/releases/download/${ODIN_VERSION}/odin-linux-amd64-${ODIN_VERSION}.tar.gz" \
    | tar -xz -C /opt && mv /opt/odin-linux-amd64-* /opt/odin
ENV PATH="/opt/odin:${PATH}"

# libsecp256k1, static, schnorrsig enabled
RUN git clone --depth 1 --branch v0.6.0 https://github.com/bitcoin-core/secp256k1 /tmp/secp \
    && cd /tmp/secp && ./autogen.sh \
    && ./configure --enable-module-schnorrsig --disable-shared --disable-tests --disable-benchmark --prefix=/usr/local \
    && make -j"$(nproc)" && make install

# SQLite amalgamation, static
RUN curl -fsSL https://sqlite.org/2025/sqlite-amalgamation-3500400.zip -o /tmp/sq.zip \
    && cd /tmp && python3 -c "import zipfile; zipfile.ZipFile('sq.zip').extractall()" 2>/dev/null \
    || (apt-get update && apt-get install -y unzip && cd /tmp && unzip -q sq.zip) \
    && cd /tmp/sqlite-amalgamation-3500400 \
    && clang -c sqlite3.c -O2 -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_COLUMN_METADATA -o sqlite3.o \
    && ar rcs /usr/local/lib/libsqlite3.a sqlite3.o

COPY src /build/src
RUN cd /build && odin build src -out:roostr-relay -o:speed \
    -extra-linker-flags:"-L/usr/local/lib" \
    && ldd roostr-relay || true

# Runtime: slim, nothing but the binary (both C libs are static).
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/roostr-relay /app/roostr-relay
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 7777
CMD ["/app/entrypoint.sh"]
