// TODO: Add package documentation for `main`, like this:
// Package main something something...
package main

import (
	"d7024e/kademlia"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	portStr := getEnv("PORT", "8000")
	port, _ := strconv.Atoi(portStr)
	ip := getEnv("IP", "0.0.0.0")

	// Get dynamically assigned container IP instead of advertised IP
	localIP, err := getLocalIP()
	if err != nil {
		slog.Error("Failed to discover container ip", "err", err)
		os.Exit(1)
	}

	listenAddr := fmt.Sprintf("%s:%d", localIP, port)

	id := kademlia.NewKademliaIDFromAddress(listenAddr)
	me := kademlia.NewContact(id, listenAddr)

	slog.Info("Starting node", "address", listenAddr, "id", id.String())

	rt := kademlia.NewRoutingTable(me)
	network := kademlia.NewUDPNetwork(me, rt)
	if err := network.Listen(ip, port); err != nil {
		slog.Error("failed to listen", "err", err)
		os.Exit(1)
	}

	kad := kademlia.NewKademlia(me, network, rt, 0)

	bootstrapIP := os.Getenv("BOOTSTRAP_IP")
	if bootstrapIP != "" && bootstrapIP != localIP {
		go func() {
			time.Sleep(2 * time.Second) // Wait for bootstrap node to start properly
			bootstrapAddr := fmt.Sprintf("%s:%d", bootstrapIP, port)
			slog.Info("Joining via bootstrap...", "target", bootstrapAddr)

			bID := kademlia.NewKademliaIDFromAddress(bootstrapAddr)
			bContact := kademlia.NewContact(bID, bootstrapAddr)
			if err := kad.Join(bContact); err != nil {
				slog.Error("Join failed", "err", err)
				return
			}
			slog.Info("Successfully joined network via bootstrap", "bootstrap", bootstrapAddr)
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

// Discovers the ip address of the docker container for this node.
func getLocalIP() (string, error) {
	// get all addresses of all interfaces
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	// loop through, excluding loopback interfaces and ipv6 addresses
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no valid non-loopback IPv4 address found")
}
