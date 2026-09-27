package main

import (
	"bufio"
	"d7024e/kademlia"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	ErrContactNotFound = errors.New("contact not found")
	ErrAmbiguousPrefix = errors.New("ambiguous prefix: multiple contacts matched")
	ErrIncorrectFormat = errors.New("incorrect format of input")
)

// ==============
// MAIN FUNCTIONS
// ==============

func main() {
	// Configure structured logger
	logLevel := slog.LevelInfo
	if strings.ToUpper(os.Getenv("LOG_LEVEL")) == "DEBUG" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	portStr := getEnv("PORT", "8000")
	port, _ := strconv.Atoi(portStr)

	// Get dynamically assigned container IP instead of advertised IP
	localIP, err := getLocalIP()
	if err != nil {
		slog.Error("Failed to discover container ip", "err", err)
		os.Exit(1)
	}

	kad, network, err := setupNode(localIP, port, os.Getenv("BOOTSTRAP_IP"))
	if err != nil {
		slog.Error("Failed to start node", "err", err)
		os.Exit(1)
	}
	defer network.Close()
	defer kad.StopReplicationWorker()

	RunCLI(kad, os.Stdin, os.Stdout)
}

// setupNode initializes network transport, routing table, and Kademlia node instance.
func setupNode(ip string, port int, bootstrapIP string) (*kademlia.Kademlia, *kademlia.UDPNetwork, error) {
	listenAddr := fmt.Sprintf("%s:%d", ip, port)
	id := kademlia.NewKademliaIDFromAddress(listenAddr)
	me := kademlia.NewContact(id, listenAddr)

	slog.Info("Initializing node", "address", listenAddr, "id", id.String())

	rt := kademlia.NewRoutingTable(me)
	ds := kademlia.NewDataStore()
	network := kademlia.NewUDPNetwork(me, rt, ds)
	if err := network.Listen(ip, port); err != nil {
		return nil, nil, err
	}

	kad := kademlia.NewKademlia(me, network, rt, ds, 0)

	if bootstrapIP != "" && bootstrapIP != ip {
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
	return kad, network, nil
}

// RunCLI handles user interaction with the node via interactive input.
func RunCLI(kad *kademlia.Kademlia, in io.Reader, out io.Writer) {
	scanner := bufio.NewScanner(in)
	ShowBanner(kad, out)

	for {
		fmt.Fprint(out, "> ")
		if !scanner.Scan() {
			if in == os.Stdin {
				select {}
			}
			return
		}

		input := strings.TrimSpace(scanner.Text())
		if handleCommand(kad, input, out) {
			return
		}
	}
}

// handleCommand executes a single CLI command string. Returns true if the command is EXIT.
func handleCommand(kad *kademlia.Kademlia, input string, out io.Writer) bool {
	fields := strings.Fields(input)
	if len(fields) == 0 {
		return false
	}

	cmd := strings.ToUpper(fields[0])

	switch cmd {
	case "EXIT":
		fmt.Fprintln(out, "Thank you for using this kademlia interactive CLI!")
		return true

	case "SHOW":
		if len(fields) < 2 {
			fmt.Fprintln(out, "Error: SHOW requires a target ('show rt' or 'show ds')")
			return false
		}
		target := strings.ToUpper(fields[1])
		switch target {
		case "RT":
			handleRT(kad, out)
		case "DS":
			handleDS(kad, out)
		default:
			fmt.Fprintf(out, "Unknown show target '%s'. Use 'show rt' or 'show ds'.\n", fields[1])
		}

	case "RT":
		handleRT(kad, out)

	case "DS":
		handleDS(kad, out)

	case "PING":
		handlePing(kad, fields, out)

	case "PUT":
		handlePut(kad, fields, out)

	case "GET":
		handleGet(kad, fields, out)

	default:
		fmt.Fprintln(out, "Unknown command. Type 'ping', 'put', 'get', 'show rt', 'show ds', or 'exit'.")
	}

	return false
}

// handlePing pings a target node by IP:PORT directly or by unique ID prefix.
func handlePing(kad *kademlia.Kademlia, fields []string, out io.Writer) {
	if kad == nil {
		fmt.Fprintln(out, "Error: Node not initialized.")
		return
	}
	if len(fields) != 2 {
		fmt.Fprintln(out, "Error: Ping requires exactly one argument: ping <IP:PORT | Unique ID prefix>")
		return
	}
	targetArg := strings.TrimSpace(fields[1])

	var toContact *kademlia.Contact
	var contacts []kademlia.Contact
	if kad.RoutingTable != nil {
		contacts = kad.RoutingTable.GetAllContacts()
	}

	// Check if argument is in IP:PORT format
	if _, _, err := net.SplitHostPort(targetArg); err == nil {
		// Valid IP:PORT endpoint
		if c, err := FindContactByAddress(contacts, targetArg); err == nil {
			toContact = c
		} else {
			// Construct direct contact
			id := kademlia.NewKademliaIDFromAddress(targetArg)
			c := kademlia.NewContact(id, targetArg)
			toContact = &c
		}
	} else {
		// Fallback to Unique ID prefix lookup
		c, err := FindContactByID(contacts, targetArg)
		if err != nil {
			fmt.Fprintf(out, "Ping failed: %v\n", err)
			return
		}
		toContact = c
	}

	start := time.Now()
	fmt.Fprintf(out, "Pinging node %s (ID: %s) ...\n", toContact.Address, truncateID(toContact.ID.String()))
	resp, err := kad.SendPing(toContact)
	if err != nil {
		fmt.Fprintf(out, "Ping error: %v\n", err)
		return
	}

	elapsedMs := float64(time.Since(start)) / float64(time.Millisecond)
	// Do not strip port from contact address
	fmt.Fprintf(out, "Ping response: %s from %s (ID: %s) in %.2f ms\n",
		resp.Type, resp.Sender.Address, truncateID(resp.Sender.ID.String()), elapsedMs)
}

// handleRT prints the routing table with full addresses (retaining ports).
func handleRT(kad *kademlia.Kademlia, out io.Writer) {
	if kad.RoutingTable == nil {
		fmt.Fprintln(out, "Routing Table is nil.")
		return
	}

	contacts := kad.RoutingTable.GetAllContacts()
	if len(contacts) == 0 {
		fmt.Fprintln(out, "Routing Table is empty.")
		return
	}

	fmt.Fprintf(out, "Routing table for node %s (%s):\n", kad.Me.ID.String(), kad.Me.Address)
	fmt.Fprintf(out, "%-11s | %-11s | %-25s\n", "Bucket No.", "Node ID", "Address")
	fmt.Fprintln(out, strings.Repeat("-", 55))

	for _, c := range contacts {
		bucketIndex := kad.RoutingTable.GetBucketIndex(c.ID)
		// Full address with port preserved
		fmt.Fprintf(out, "%-11d | %-11s | %-25s\n", bucketIndex, truncateID(c.ID.String()), c.Address)
	}
}

// handleDS prints contents of the data store.
func handleDS(kad *kademlia.Kademlia, out io.Writer) {
	if kad.DataStore == nil {
		fmt.Fprintln(out, "DataStore not initialized.")
		return
	}

	keys := kad.DataStore.GetAllKeys()
	if len(keys) == 0 {
		fmt.Fprintln(out, "DataStore is currently empty.")
		return
	}

	fmt.Fprintf(out, "DataStore has %d items:\n", len(keys))
	for i, k := range keys {
		val, _ := kad.DataStore.Get(k)
		fmt.Fprintf(out, "[%d] Key: %s | Bytes: %d | Data: %q\n",
			i+1, truncateID(k.String()), len(val), string(val))
	}
}

// handlePut stores a local file's content under its cryptographic SHA-256 hash.
func handlePut(kad *kademlia.Kademlia, fields []string, out io.Writer) {
	if kad == nil {
		fmt.Fprintln(out, "Error: Node not initialized.")
		return
	}
	if len(fields) != 2 {
		fmt.Fprintln(out, "Error: PUT requires exactly 1 argument: PUT <filename>")
		return
	}
	filename := fields[1]

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(out, "Error reading file '%s': %v\n", filename, err)
		return
	}

	key, err := kad.Store(data)
	if err != nil {
		fmt.Fprintf(out, "Error storing data: %v\n", err)
		return
	}

	fmt.Fprintf(out, "File '%s' has been stored successfully!\n", filename)
	fmt.Fprintf(out, "Key: %s\n", key.String())
}

// handleGet retrieves data for a given key, either printing it or saving to file.
func handleGet(kad *kademlia.Kademlia, fields []string, out io.Writer) {
	if kad == nil {
		fmt.Fprintln(out, "Error: Node not initialized.")
		return
	}
	if len(fields) < 2 || len(fields) > 3 {
		fmt.Fprintln(out, "Error: GET requires either 2 or 3 arguments: GET <Key> [filename]")
		return
	}

	keyHex := strings.TrimSpace(fields[1])
	if len(keyHex) != 64 {
		fmt.Fprintf(out, "Error: Invalid key '%s'. Key must be a 64-character hexadecimal SHA-256 hash.\n", keyHex)
		return
	}
	if _, err := hex.DecodeString(keyHex); err != nil {
		fmt.Fprintf(out, "Error: Invalid hexadecimal key '%s': %v\n", keyHex, err)
		return
	}
	key := kademlia.NewKademliaID(keyHex)

	data, responderContact, err := kad.LookupDataByID(key)
	if err != nil {
		fmt.Fprintf(out, "Error retrieving data from key '%s': %v\n", truncateID(key.String()), err)
		return
	}

	if len(fields) == 3 {
		filename := fields[2]
		if err := os.WriteFile(filename, data, 0644); err != nil {
			fmt.Fprintf(out, "Error saving file '%s': %v\n", filename, err)
			return
		}
		fmt.Fprintf(out, "Data saved to file '%s'\n", filename)
	} else {
		fmt.Fprintf(out, "Key: %s | Bytes: %d | Data: %q\n", truncateID(key.String()), len(data), string(data))
	}

	if responderContact != nil {
		// Preserving full address with port
		fmt.Fprintf(out, "Received from node: %s (ID: %s)\n", responderContact.Address, truncateID(responderContact.ID.String()))
	}
}

// =================
// HELPER FUNCTIONS
// =================

// ShowBanner prints the interactive CLI menu for the client.
func ShowBanner(kad *kademlia.Kademlia, out io.Writer) {
	fmt.Fprintf(out, `==================================================
Kademlia Interactive CLI - Connected Node
ID:   %s
ADDR: %s
==================================================
Options:
- PING <IP:PORT | Unique ID prefix>
- PUT <filename>
- GET <KEY> [filename]
- SHOW RT (or RT)
- SHOW DS (or DS)
- EXIT
--------------------------------------------------
`, kad.Me.ID.String(), kad.Me.Address)
}

// truncateID truncates an ID string to first and last 4 characters.
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

// FindContactByAddress finds a contact with the matching address in the list.
func FindContactByAddress(contacts []kademlia.Contact, targetAddr string) (*kademlia.Contact, error) {
	for i := range contacts {
		if contacts[i].Address == targetAddr {
			return &contacts[i], nil
		}
	}
	return nil, ErrContactNotFound
}

// FindContactByID searches contacts for a unique ID prefix match.
func FindContactByID(contacts []kademlia.Contact, IDprefix string) (*kademlia.Contact, error) {
	prefix := strings.ToLower(strings.TrimSpace(IDprefix))
	var matched *kademlia.Contact
	matchCount := 0

	for i := range contacts {
		idHex := strings.ToLower(contacts[i].ID.String())
		if strings.HasPrefix(idHex, prefix) {
			matchCount++
			matched = &contacts[i]
		}
	}

	if matchCount == 0 {
		return nil, ErrContactNotFound
	}
	if matchCount > 1 {
		return nil, ErrAmbiguousPrefix
	}

	return matched, nil
}

// getLocalIP discovers the IPv4 address of the local network interface.
func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no valid non-loopback IPv4 address found")
}
