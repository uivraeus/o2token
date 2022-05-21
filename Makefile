all: build

clean:
	rm -f o2token

build:
	go build -o o2token

run:
	go run .
	