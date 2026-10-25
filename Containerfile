# Everything (dependency download, vet, build, tests) happens inside this image.
FROM docker.io/library/golang:1.25-alpine AS build
WORKDIR /app
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false GOCACHE=/tmp/gocache GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN go vet ./... && go build -trimpath -ldflags '-s -w' -o /out/airvpn-go .

FROM scratch AS out
COPY --from=build /out/airvpn-go /
