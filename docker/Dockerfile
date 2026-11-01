# One image for every role in the test environment; the entrypoint picks the role.
ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/smesh-server ./cmd/Server \
 && CGO_ENABLED=0 go build -trimpath -o /out/smesh-client ./cmd/Client

FROM alpine:3.22
# iproute2 for the TUN setup and routes; ping and tcpdump for poking at the network.
RUN apk add --no-cache iproute2 iputils-ping tcpdump
COPY --from=build /out/ /usr/local/bin/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
