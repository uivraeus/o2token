all: build

clean:
	rm -rf bin/

build: build_o2token build_jwt
	@echo
	@echo Build output in bin/ directory:
	@echo -------------------------------
	@ls -1sh bin/*

build_o2token:
	go build -o bin/o2token

build_jwt:
	cd jwt && go build -o ../bin/jwt

run:
	go run .
	