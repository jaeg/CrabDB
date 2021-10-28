REPO = jaeg/crabdb
BINARY = crabdb
VERSION = 1.1.0

bin:
	mkdir bin

vendor:
	go mod vendor

image: build-linux
	docker build -t $(REPO):$(VERSION) . --build-arg binary=$(BINARY)-linux --build-arg version=$(VERSION)

image-pi: build-linux-pi

	docker build -t $(REPO):$(VERSION)-pi . --build-arg binary=$(BINARY)-linux-pi --build-arg version=$(VERSION)

run:
	go run -mod=vendor .

build: bin
	go build -mod=vendor -o ./bin/$(BINARY)

build-linux: bin
	env GOOS=linux GOARCH=amd64 go build -mod=vendor -o ./bin/$(BINARY)-linux

build-linux-pi: bin
	env GOOS=linux GOARCH=arm GOARM=7 go build -mod=vendor -o ./bin/$(BINARY)-linux-pi

publish-pi:
	docker push $(REPO):$(VERSION)-pi
	docker tag $(REPO):$(VERSION)-pi $(REPO):latest-pi
	docker push $(REPO):latest-pi

publish:
	docker push $(REPO):$(VERSION)
	docker tag $(REPO):$(VERSION) $(REPO):latest
	docker push $(REPO):latest

.PHONY: update-go-deps
update-go-deps:
	@echo ">> updating Go dependencies"
	@for m in $$(go list -mod=readonly -m -f '{{ if and (not .Indirect) (not .Main)}}{{.Path}}{{end}}' all); do \
		go get $$m; \
	done
	go mod tidy
ifneq (,$(wildcard vendor))
	go mod vendor
endif