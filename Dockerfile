FROM golang:1.15-alpine as build

COPY . /build
RUN apk add libpcap libpcap-dev gcc git musl-dev;
RUN cd /build; CGO_ENABLED=1 GOBIN=/bin/ go install ./cmd/go-flowprobe;

FROM alpine as prod

RUN apk add libpcap;

COPY --from=build /bin/go-flowprobe /bin/go-flowprobe

CMD ["/bin/go-flowprobe"]
