FROM alpine:3.4

MAINTAINER mozhuli <weidonglee27@gmail.com>

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
ENV KUBE_SNIFFER_VERSION "1.0"

# Add source files.
ADD *.go /go/src/github.com/mozhuli/kube-sniffer/
ADD pkg /go/src/github.com/mozhuli/kube-sniffer/pkg
ADD vendor /go/src/github.com/mozhuli/kube-sniffer/vendor

RUN set -ex \
	&& apk add --no-cache --virtual .build-deps \
		bash \
		musl-dev \
		openssl \
		go \
		gcc \
		libpcap-dev \
		ca-certificates \
    && cd /go/src/github.com/mozhuli/kube-sniffer \
    && go build -v -i -o /bin/kube-sniffer -ldflags "-X main.VERSION=$(KUBE_SNIFFER_VERSION) -s -w" kube-sniffer.go \
	&& rm -rf /go \
	&& apk del .build-deps
CMD ["kube-sniffer"]
