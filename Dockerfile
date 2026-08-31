# syntax=docker/dockerfile:1

FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/cacheserv ./cmd/cacheserv

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cacheserv /usr/local/bin/cacheserv
WORKDIR /var/cache
VOLUME ["/var/cache"]
EXPOSE 8765
ENTRYPOINT ["cacheserv"]
