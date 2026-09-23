// TODO: Add package documentation for `main`, like this:
// Package main something something...
package main

import (
	"bufio"
	"d7024e/kademlia"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	// Configure structured logger
	logLevel := slog.LevelInfo
	if strings.ToUpper(os.Getenv("LOG_LEVEL")) == "DEBUG" {
		logLevel = slog.LevelDebug
	}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(handler))

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
	ds := kademlia.NewDataStore()
	network := kademlia.NewUDPNetwork(me, rt, ds)
	if err := network.Listen(ip, port); err != nil {
		slog.Error("failed to listen", "err", err)
		os.Exit(1)
	}

	kad := kademlia.NewKademlia(me, network, rt, ds, 0)

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

	kad.StartReplicationWorker(kademlia.DefaultReplicationInterval)
	defer kad.StopReplicationWorker()

	runCLI(kad)
}

func ShowBanner(kad *kademlia.Kademlia) {
	fmt.Println("==================================================")
	fmt.Printf(" Kademlia Interactive CLI - Connected Node\n")
	fmt.Printf(" ID:   %s\n", kad.Me.ID.String())
	fmt.Printf(" ADDR: %s\n", kad.Me.Address)
	fmt.Println("==================================================")
	fmt.Println(`Options:
- PING <IP:PORT>
- PUT <filename>
- GET <KEY> <optional: filename>
- EXIT
- RT
- DS 
--------------------------------------------------`)
}

func runCLI(kad *kademlia.Kademlia) {
	scanner := bufio.NewScanner(os.Stdin)

	ShowBanner(kad)

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			// If stdin reached EOF (e.g. non-interactive / daemon / swarm mode),
			// block to keep node alive.
			select {}
		}

		input := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(input)

		if len(fields) == 0 {
			ShowBanner(kad)
			continue
		}

		cmd := strings.ToUpper(fields[0])

		switch cmd {
		case "EXIT":
			fmt.Println("Thank you for using this kademlia interactive CLI!")
			os.Stdin.Close()
			return

		// Pinging node A from node B
		case "PING":
			if len(fields) != 2 {
				fmt.Println("Error: Ping requires exactly one argument: IP:PORT")
				continue
			}
			ip, port, ok := strings.Cut(fields[1], ":")
			if !ok || port == "" || ip == "" {
				fmt.Println("Error: Invalid format, expected IP:PORT")
				continue
			}
			targetAddr := fmt.Sprintf("%s:%s", ip, port)
			dummyContact := kademlia.NewContact(kademlia.NewRandomKademliaID(), targetAddr)
			if resp, err := kad.SendPing(&dummyContact); err != nil {
				fmt.Printf("Ping error: %v \n", err)
			} else {
				fmt.Printf("Ping response: %s from %s (ID: %s)\n", resp.Type, resp.Sender.Address, resp.Sender.ID)
			}

		// Retrieve the routing table
		case "RT":
			contacts := kad.RoutingTable.GetAllContacts()
			if len(contacts) == 0 {
				fmt.Println("Routing Table is empty.")
				continue
			}
			fmt.Printf("Routing table for node %s (%s): \n", kad.Me.ID.String(), kad.Me.Address)
			fmt.Printf("%-4s | %-11s | %-21s \n", "No.", "Node ID", "Address")
			fmt.Println(strings.Repeat("-", 40))

			for i, c := range contacts {
				fmt.Printf("%-4d | %-11s | %-21s\n", i+1, truncateID(c.ID.String()), c.Address)
			}

		case "PUT":
			if len(fields) != 2 {
				fmt.Printf("Error: PUT requires exactly 1 argument: PUT <filename>\n")
				continue
			}
			filename := fields[1]

			// read file contents
			data, err := os.ReadFile(filename)
			if err != nil {
				fmt.Printf("Error reading file '%s': %v \n", filename, err)
				continue
			}

			// pass data to store function
			key, err := kad.Store(data)
			if err != nil {
				fmt.Printf("Error storing data: %v\n", err)
				continue
			}

			// print key
			fmt.Printf("File '%s' has been stored successfully!\n", filename)
			fmt.Printf("Key: %s \n", key.String())

		case "GET":
			if len(fields) < 2 || len(fields) > 3 {
				fmt.Printf("Error: GET requires either 2 or 3 arguments: GET <Key> <optional: filename>")
				continue
			}

			keyHex := strings.TrimSpace(fields[1])
			key := kademlia.NewKademliaID(keyHex)

			// retrieve data at key
			data, responderContact, err := kad.LookupDataByID(key)
			if err != nil {
				fmt.Printf("Error retrieving data from key '%s'", truncateID(key.String()))
				continue

			}
			// if filename is given
			if len(fields) == 3 {
				filename := fields[2]
				err := os.WriteFile(filename, data, 0644)
				if err != nil {
					fmt.Printf("Error saving file '%s': %v \n", filename, err)
					continue
				}
				fmt.Printf("Data saved to file '%s'\n", filename)
			} else {
				// if filename is not given
				// print key and data to user
				fmt.Printf("Key: %s | Bytes: %d | Data: %q\n", truncateID(key.String()), len(data), string(data))
			}
			if responderContact != nil {
				fmt.Printf("Recieved from node: %s (ID: %s)\n", responderContact.Address, truncateID(responderContact.ID.String()))
			}

		case "DS":
			// Dump all stored key-value pairs in this node's local store
			if kad.DataStore == nil {
				fmt.Println("DataStore not initialized.")
				continue
			}
			keys := kad.DataStore.GetAllKeys()
			if len(keys) == 0 {
				fmt.Println("DataStore is currently empty.")
				continue
			}
			fmt.Printf("DataStore has %d items:\n", len(keys))
			for i, k := range keys {
				val, _ := kad.DataStore.Get(k)
				fmt.Printf("[%d] Key: %s | Bytes: %d | Data: %q\n",
					i+1, truncateID(k.String()), len(val), string(val))
			}

		default:
			fmt.Println("Unknown command. Type 'ping', 'lookup', 'rt', or 'exit'.")
		}
	}

}

// Truncates ID to last- and first 4 characters
func truncateID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return fmt.Sprintf("%s...%s", id[:4], id[len(id)-4:])
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
