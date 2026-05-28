FROM golang:1.26.2-alpine AS build-deps

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN apk add --no-cache ca-certificates git

WORKDIR $GOPATH/src/github.com/calypr/arborist/

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN GITCOMMIT=$(git rev-parse HEAD) \
    GITVERSION=$(git describe --always --tags) \
    && go build \
    -ldflags="-X 'github.com/calypr/arborist/arborist/version.GitCommit=${GITCOMMIT}' -X 'github.com/calypr/arborist/arborist/version.GitVersion=${GITVERSION}'" \
    -o bin/arborist

FROM alpine:3.22
RUN apk add --no-cache bash ca-certificates jq libcap postgresql15-client
COPY --from=build-deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-deps /go/src/github.com/calypr/arborist/ /go/src/github.com/calypr/arborist/
RUN setcap 'cap_net_bind_service=+ep' /go/src/github.com/calypr/arborist/bin/arborist
WORKDIR /go/src/github.com/calypr/arborist/
USER nobody
CMD ["/go/src/github.com/calypr/arborist/bin/arborist"]
