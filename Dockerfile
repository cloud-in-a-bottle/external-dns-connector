FROM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first so a code-only change doesn't re-download 20 provider SDKs.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
# CGO off keeps the binary static: the sqlite driver is pure Go (modernc), so nothing needs libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dns-connector ./cmd/dns-connector

FROM alpine:3.20
# Provider APIs are all HTTPS, so the image needs the CA bundle. tzdata keeps audit timestamps sane.
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/dns-connector /usr/local/bin/dns-connector

EXPOSE 8080
CMD ["dns-connector"]
