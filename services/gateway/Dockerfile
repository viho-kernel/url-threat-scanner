FROM node:24-bookworm-slim AS web-build

WORKDIR /web

COPY web/package.json web/package-lock.json ./

RUN npm ci

COPY web/ ./

RUN npm run build

# Test and compile the Go Gateway.
FROM golang:1.26.8-bookworm AS go-build

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./

COPY --from=web-build /web/dist ./web/dist

RUN go test ./...

RUN CGO_ENABLED=0 go build -o /gateway .


# Minimal runtime image.
FROM scratch

COPY --from=go-build /gateway /gateway

USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/gateway"]