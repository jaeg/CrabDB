REPO = jaeg/crabdb
BINARY = crabdb
VERSION = 1.0.2

image: build-linux
	docker build -t $(REPO):$(VERSION) . --build-arg binary=$(BINARY)-linux --build-arg version=$(VERSION)

image-pi: build-linux-pi

	docker build -t $(REPO):$(VERSION)-pi . --build-arg binary=$(BINARY)-linux-pi --build-arg version=$(VERSION)

build:
	go build -o pkg/$(BINARY)

build-linux:
	env GOOS=linux GOARCH=amd64 go build -o pkg/$(BINARY)-linux

build-linux-pi:
	env GOOS=linux GOARCH=arm GOARM=7 go build -o pkg/$(BINARY)-linux-pi

publish-pi:
	docker push $(REPO):$(VERSION)-pi
	docker tag $(REPO):$(VERSION)-pi $(REPO):latest-pi
	docker push $(REPO):latest-pi

publish:
	docker push $(REPO):$(VERSION)
	docker tag $(REPO):$(VERSION) $(REPO):latest
	docker push $(REPO):latest