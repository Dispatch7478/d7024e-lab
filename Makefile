NODES ?= 20 
NODE ?= 1

.PHONY: build up down restart logs attach attach-bootstrap test clean 

build:
	CGO_ENABLED=0 GOOS=linux go build -o kadlab ./main.go
	docker build . -t kadlab 

up: 
	docker compose up -d --scale kademliaNodes=${NODES}

run: down build up 

down:
	docker compose down 

restart: down run 

logs:
	docker compose logs -f 

attach: 
	-docker attach --detach-keys="ctrl-c" d7024e-lab-kademliaNodes-$(NODE)

attach-bootstrap:
	docker attach kademlia-bootstrap

test:
	go test -v -cover -count=1 ./...
