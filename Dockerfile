FROM golang:1.26.2-alpine AS build-deps

ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk add --no-cache ca-certificates git

WORKDIR /src/arborist

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN GITCOMMIT=$(git rev-parse HEAD) \
    GITVERSION=$(git describe --always --tags) \
    && go build \
        -ldflags="-X 'github.com/calypr/arborist/internal/version.GitCommit=${GITCOMMIT}' -X 'github.com/calypr/arborist/internal/version.GitVersion=${GITVERSION}'" \
        -o /tmp/arborist .

FROM alpine:3.22
RUN apk add --no-cache bash ca-certificates jq libcap postgresql15-client
COPY --from=build-deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-deps /tmp/arborist /usr/local/bin/arborist
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/arborist
USER nobody
CMD ["/usr/local/bin/arborist"]
