# syntax=docker/dockerfile:1
# Vulnizard: one binary, one SQLite file.
#   docker build -t vulnizard .
#   docker run -d --name vulnizard -p 8000:8000 -v vulnizard-data:/data vulnizard
#   docker exec -it vulnizard vulnizard user create admin --admin
FROM rust:1-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bins \
    && install -Dt /out target/release/vulnizard target/release/vulnizard-collector

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin vulnizard \
    && install -d -o vulnizard -g vulnizard /data /keys
COPY --from=build /out/vulnizard /out/vulnizard-collector /usr/local/bin/
COPY docker/container.toml /etc/vulnizard/config.toml
USER vulnizard
WORKDIR /data
VOLUME /data
EXPOSE 8000
# The configuration file sets the defaults; the Admin pages override them and are stored in the database
ENTRYPOINT ["vulnizard", "--config", "/etc/vulnizard/config.toml"]
CMD ["serve"]
