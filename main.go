// TODO: Add package documentation for `main`, like this:
// Package main something something...
package main

import (
	"d7024e/kademlia"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

func main() {
	portStr := getEnv("PORT", "8000")
	port, _ := strconv.Atoi(portStr)
	ip := getEnv("IP", "0.0.0.0")
	advertisedIP := getEnv("ADVERTISED_IP", "127.0.0.1")

	listenAddr := fmt.Sprintf("%s:%d", advertisedIP, port)

	id := kademlia.NewKademliaIDFromAddress(listenAddr)
	me := kademlia.NewContact(id, listenAddr)

	slog.Info("Starting node", "address", listenAddr, "id", id.String())

	rt := kademlia.NewRoutingTable(me)
	network := kademlia.NewUDPNewtork(me, rt)
	if err := network.Listen(ip, port); err != nil {
		slog.Error("failed to listen", "err", err)
		os.Exit(1)
	}

	pingTarget := os.Getenv("PING_TARGET")
	if pingTarget != "" {
		go func() {
			time.Sleep(2 * time.Second) // Wait for target node to start
			slog.Info("Pinging target...", "target", pingTarget)

			targetID := kademlia.NewKademliaIDFromAddress(pingTarget)

			targetContact := kademlia.NewContact(targetID, pingTarget)

			start := time.Now()

			res, err := network.SendPingMessage(&targetContact)

			if err != nil {
				slog.Error("Ping failed", "err", err)
				return
			}

			rtt := time.Since(start)

			slog.Info("Ping worked", "from", res.Sender.Address, "rtt", rtt, "txID", res.TransactionID)
		}()
	}

	select {} // Block to keep container up
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
