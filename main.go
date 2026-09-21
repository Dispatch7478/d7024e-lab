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
- LOOKUP <Recipient_IP:PORT> <Target_HexID>
- RT
- EXIT
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

		// Lookup from nodeA to NodeB about target
		case "LOOKUP":
			if len(fields) != 3 {
				fmt.Println("Error: Lookup requires exactly two arguments: Recipient_IP:PORT Target-ID")
				continue
			}

			recipientAddr := fields[1]
			targetHex := fields[2]

			// validate IP:PORT format
			if ip, port, ok := strings.Cut(recipientAddr, ":"); !ok || port == "" || ip == "" {
				fmt.Println("Error: Invalid Node format, expected IP:PORT")
				continue
			}

			// Validate hex format of ID
			if len(targetHex) != 64 {
				fmt.Println("Error: Target ID must be 64-character hexadecimal string")
				continue
			}

			// search for recipient in routing table
			var recipientContact *kademlia.Contact
			for _, neighbor := range kad.RoutingTable.GetAllContacts() {
				if neighbor.Address == recipientAddr {
					c := neighbor
					recipientContact = &c
					break
				}
			}

			if recipientContact == nil {
				fmt.Println("Error: recipient not in routing table")
				continue
			}

			targetID := kademlia.NewKademliaID(targetHex)

			fmt.Printf("Querying %s for contacts closest to %s... \n", recipientContact.Address, truncateID(targetID.String()))
			contacts, err := kad.Network.SendFindContactMessage(targetID, recipientContact)
			if err != nil {
				fmt.Printf("Lookup error: %v\n", err)
				continue
			}
			if len(contacts) == 0 {
				fmt.Println("Recipient returned 0 contacts")
				continue
			}

			fmt.Printf("Success! Received %d closest contacts from %s \n", len(contacts), recipientContact.Address)
			for i, contact := range contacts {
				fmt.Printf("[%d] ID: %s | Address: %s \n", i+1, truncateID(contact.ID.String()), contact.Address)
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
