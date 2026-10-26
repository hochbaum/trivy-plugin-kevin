GOOS=linux
GOARCH=linux/amd64

all:
	mkdir -p dist
	cp plugin.yaml dist/
	CGO_ENABLED=0 go build -o dist/trivy-plugin-kevin ./...
	tar cvzf dist/trivy-plugin-kevin.tar.gz -C dist trivy-plugin-kevin plugin.yaml

clean:
	rm -r dist/