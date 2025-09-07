all: build

clean:
	rm -rf bin/

ifeq ($(GOOS),windows)
outputFileExt=.exe
endif
ifndef OUTPUT_SUFFIX
build: export OUTPUT_SUFFIX=$(outputFileExt)
endif
build: build_o2token build_jwt
	@echo
	@echo Build output in bin/ directory:
	@echo -------------------------------
	@ls -1sh bin/*

build_o2token:
	go build -buildvcs=false -o bin/o2token${OUTPUT_SUFFIX}

build_jwt:
	cd jwt && go build -buildvcs=false -o ../bin/jwt${OUTPUT_SUFFIX}

run:
	go run .
