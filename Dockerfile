FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends curl xz-utils ca-certificates && rm -rf /var/lib/apt/lists/*
ARG ZIG_VERSION=0.13.0
RUN curl -fsSL https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz | tar -xJ -C /opt \
 && ln -s /opt/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/local/bin/zig
WORKDIR /app
COPY . .
RUN zig build -Doptimize=ReleaseSafe

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/zig-out/bin/ziglink /app/ziglink
COPY --from=build /app/src /app/src
EXPOSE 8081
CMD ["/app/ziglink"]
