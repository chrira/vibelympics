APP_NAME := vibelympics
IMAGE := $(APP_NAME):round1
PORT ?= 8080

.PHONY: all build run clean docker-build docker-run

all: build

build:
	@mkdir -p bin
	go build -o bin/$(APP_NAME)

run: build
	PORT=$(PORT) ./bin/$(APP_NAME)

clean:
	rm -rf bin

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p $(PORT):8080 $(IMAGE)
SHELL := /bin/bash

BINARY := bin/vibelympics
IMAGE := vibelympics:round1
PORT ?= 8080

.PHONY: all build run docker-build docker-run clean tidy

all: build

build:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o $(BINARY)

run: build
	PORT=$(PORT) ./$(BINARY)

docker-build:
	docker build -t $(IMAGE) .

docker-run: docker-build
	docker run --rm -p $(PORT):8080 $(IMAGE)

clean:
	rm -rf bin

tidy:
	go mod tidy
