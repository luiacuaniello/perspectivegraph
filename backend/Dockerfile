# syntax=docker/dockerfile:1
# Multi-stage build producing a tiny static AegisGraph binary.

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO disabled → fully static binary (pure-Go resolver), runs on distroless.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aegisgraph ./cmd/aegisgraph

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegisgraph /aegisgraph
COPY --from=build /src/testdata /testdata
EXPOSE 8080 8081
USER nonroot:nonroot
ENTRYPOINT ["/aegisgraph"]
