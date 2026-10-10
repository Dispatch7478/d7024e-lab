NODES ?= 50 
NODE ?= 1

.PHONY: build up down restart logs attach attach-bootstrap test clean reset wipe

build:
	CGO_ENABLED=0 GOOS=linux go build -o kadlab ./cmd/node
	docker build . -t kadlab 

up: 
	docker compose up -d --scale kademliaNodes=${NODES}

run: down build up 

down:
	docker compose down 

clean: down
	rm -rf keys/*
	rm -f installed_*.txt downloaded_*.txt

wipe: clean

reset: clean up

restart: down up 

logs:
	docker compose logs -f 

attach: 
	-docker attach --detach-keys="ctrl-c" d7024e-lab-kademliaNodes-$(NODE)

attach-bootstrap:
	docker attach kademlia-bootstrap

test:
	go test -v -cover -count=1 ./...
