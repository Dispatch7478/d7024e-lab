// TODO: Add package documentation for `main`, like this:
// Package main something something...
package main

import (
	"d7024e/kademlia"
	"log"
	"os"
)

func main(){
	port := 8000
	bootstrapIP := os.Getenv("BOOTSTRAP_IP")

	_, err := kademlia.NewNode(port, bootstrapIP)
	if err != nil {
		log.Fatalf("Fata node initialization error: %v", err)
	}

	select{}
}
