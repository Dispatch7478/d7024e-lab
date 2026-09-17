NODES ?= 5 
NODE ?= 1

.PHONY: build up down restart logs attach test clean 

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o kadlab ./main.go
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
	docker attach d7024e-lab-kademliaNodes-${NODE}

test:
	go test -v -cover -count=1 



