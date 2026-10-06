FROM golang:1.24-alpine AS build

ARG KITERUNNER_COMMIT=e7a7fa635c2271cb5aeea7a885c1dc66774bb5c7

RUN apk add --no-cache git patch ca-certificates
WORKDIR /src
RUN git clone https://github.com/assetnote/kiterunner.git . \
    && git checkout --detach "${KITERUNNER_COMMIT}" \
    && test "$(git rev-parse HEAD)" = "${KITERUNNER_COMMIT}"
COPY remove-default-x-forwarded-for.patch /tmp/remove-default-x-forwarded-for.patch
RUN patch -p1 < /tmp/remove-default-x-forwarded-for.patch \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
       -ldflags="-s -w -X github.com/assetnote/kiterunner/cmd/kiterunner/cmd.Version=1.0.2-safe" \
       -o /out/kr ./cmd/kiterunner

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    && addgroup -g 1000 scanner \
    && adduser -D -H -u 1000 -G scanner scanner
COPY --from=build /out/kr /usr/local/bin/kr
USER 1000:1000
ENTRYPOINT ["kr"]
