FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/collision-gateway ./cmd/collision-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/collision-gateway /collision-gateway
EXPOSE 8787
ENTRYPOINT ["/collision-gateway"]
