FROM alpine:3.6

MAINTAINER mozhuli <weidonglee27@gmail.com>

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# Add source files.
ADD *.go /go/src/github.com/mozhuli/kube-sniffer/
ADD pkg /go/src/github.com/mozhuli/kube-sniffer/pkg
ADD vendor /go/src/github.com/mozhuli/kube-sniffer/vendor

RUN set -ex \
	&& apk update && apk add --no-cache --virtual .build-deps \
		bash \
		musl-dev \
		openssl \
		gcc \
		libpcap-dev \
		go \
		ca-certificates \
	
    && cd /go/src/github.com/mozhuli/kube-sniffer \
    && go build -v  -o /bin/kube-sniffer -ldflags "-X main.VERSION=1.0 -s -w" kube-sniffer.go \
	&& rm -rf /go \
	&& apk del .build-deps 
	
CMD ["kube-sniffer"]
