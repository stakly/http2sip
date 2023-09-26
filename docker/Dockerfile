FROM golang:alpine AS http2sip-builder
LABEL stage=gobuilder
WORKDIR /opt/http2sip
COPY auth auth
COPY go.mod go.sum configExample.txt http2sip.go .
RUN find .
RUN go mod download && go mod verify
RUN go build -trimpath -ldflags="-s -w" -v http2sip.go

FROM alpine
LABEL maintainer="stkl"
WORKDIR /opt/http2sip
RUN apk add --no-cache tzdata ca-certificates
#gcompat
ENV TZ=Asia/Yekaterinburg
RUN ln -fs /usr/share/zoneinfo/Asia/Yekaterinburg /etc/localtime

COPY --from=http2sip-builder /opt/http2sip/http2sip .
#COPY config.yml .
RUN addgroup z \
    && adduser -s /bin/sh -h /opt/http2sip -D -H z -G z \
    && chown -R z:z /opt/http2sip
USER z
ENTRYPOINT [ "/opt/http2sip/http2sip" ]
#CMD ["/opt/http2sip/http2sip"]
