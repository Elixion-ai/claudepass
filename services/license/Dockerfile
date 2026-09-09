# ClaudePass license service (CLA-15). A static, CGo-free binary —
# modernc.org/sqlite is pure Go, so CGO_ENABLED=0 works and the final image
# needs no libc.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/license-service ./services/license

FROM scratch
COPY --from=build /out/license-service /license-service
# LICENSE_DB_PATH should point under /data, the volume fly.toml mounts.
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/license-service"]
