all: build

clean:
	rm -f o2token
	rm -f jtw/jwt

build: build_o2token build_jwt

build_o2token:
	go build

build_jwt:
	cd jwt && go build

run:
	go run .
	