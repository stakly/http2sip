build:
	go build -o http2sip -v -x -trimpath -ldflags="-s -w" http2sip.go

clean:
	rm -f http2sip
