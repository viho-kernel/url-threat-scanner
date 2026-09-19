
#This is temporary build environment
FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN go test ./...
RUN CGO_ENABLED=0 go build -o /gateway .
#compile/test stage
FROM scratch
COPY --from=build /gateway /gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/gateway"]
#binary stage