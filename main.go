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
	"errors"
)

var (
	ErrContactNotFound = errors.New("contact not found")
	ErrAmbigousPrefix = errors.New("ambigous prefix: multiple contacts matched")
	ErrIncorrectFormat = errors.New("Incorrect format of input")
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



// RunCLI is the main interactive CLI function for displaying
// and adding functionality to the cli in addition handles user input
func runCLI(kad *kademlia.Kademlia) {
	
	scanner := bufio.NewScanner(os.Stdin)
	
	// Display menu
	ShowBanner(kad)

	// main loop
	for {

		fmt.Print("> ")
		if !scanner.Scan() {
			select {}
		}

		// recive input and split into fields
		input := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(input)

		if len(fields) == 0 {
			ShowBanner(kad)
			continue
		}

		// Isolate main command: PING, RT, DS, GET, PUT
		cmd := strings.ToUpper(fields[0])

		// Swtich case for each command option 
		switch cmd {
		
			// EXIT: Exit cli
		case "EXIT":
			fmt.Println("Thank you for using this kademlia interactive CLI!")
			os.Stdin.Close()
			return

			// PING: Pinging target node
		case "PING":

			// Validate input
			if len(fields) != 2 {
				fmt.Println("Error: Ping requires exactly one argument: <Unique ID prefix>")
				continue
			}
			IDprefix := fields[1]

			// check if the target contact exists in the nodes routing table
			contacts := kad.RoutingTable.GetAllContacts()
			toContact, err := FindContactByID(contacts, IDprefix)
			if err != nil {
				fmt.Printf("Ping failed: %v \n", err)
				continue
			}

			// initiate the ping
			start := time.Now()
			fmt.Printf("Pinging node with ID prefix: %s ... \n", IDprefix)
			if resp, err := kad.SendPing(toContact); err != nil {
				fmt.Printf("Ping error: %v \n", err)
			} else {
				// successful ping
				t := time.Now()
				diff := t.Sub(start)
				elapsedMs := float64(diff) / float64(time.Millisecond)
				ip, err := trimPortFromAddress(resp.Sender.Address)
				if err != nil{
					fmt.Printf("Error on address trim: %v", err)
					continue
				}
				fmt.Printf("Ping response: %s from %s (ID: %s) in %.2f ms \n", resp.Type, ip, truncateID(resp.Sender.ID.String()), elapsedMs)
			}

			// RT: Retrieve the routing table
		case "RT":

			// Query for routing table contents
			contacts := kad.RoutingTable.GetAllContacts()
			if len(contacts) == 0 {
				fmt.Println("Routing Table is empty.")
				continue
			}

			// Output table header 
			fmt.Printf("Routing table for node %s (%s): \n", kad.Me.ID.String(), kad.Me.Address)
			fmt.Printf("%-11s | %-11s | %-21s \n", "Bucket No.", "Node ID", "Address")
			fmt.Println(strings.Repeat("-", 40))
			
			// Routing table entries 
			for _, c := range contacts {
				ip, err := trimPortFromAddress(c.Address)
				if err != nil {
					fmt.Printf("Error on address trim %v", err)
					continue
				}
				bucketIndex := kad.RoutingTable.GetBucketIndex(c.ID)
				fmt.Printf("%-11d | %-11s | %-21s\n", bucketIndex, truncateID(c.ID.String()), ip)
			}

		// PUT: upload contents of file under its hash 
		case "PUT":

			// Validate input
			if len(fields) != 2 {
				fmt.Printf("Error: PUT requires exactly 1 argument: PUT <filename>\n")
				continue
			}
			filename := fields[1]

			// Read file contents
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

			// Print key
			fmt.Printf("File '%s' has been stored successfully!\n", filename)
			fmt.Printf("Key: %s \n", key.String())
	
		// GET: download value associated with given key 
		case "GET":

			// Validate input
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
			// If filename is given
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
				fmt.Printf("Key: %s | Bytes: %d | Data: %q\n", truncateID(key.String()), len(data), string(data))
			}
			if responderContact != nil {
				fmt.Printf("Recieved from node: %s (ID: %s)\n", responderContact.Address, truncateID(responderContact.ID.String()))
			}

		// DS: prints the data store 
		case "DS":
			
			// If no data store has been initialized
    	if kad.DataStore == nil {
				fmt.Println("DataStore not initialized.")
				continue
			}

			// Get keys stored in data store and print if any exist 
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

		// Print command options
		default:
			fmt.Println("Unknown command. Type 'ping', 'lookup', 'rt', or 'exit'.")
		}
	}

}


// =================
// HELPER FUNCTIONS 
// =================

// ShowBanner prints the interactive CLI menu for the client.
func ShowBanner(kad *kademlia.Kademlia) {
	fmt.Printf(`==================================================
Kademlia Interactive CLI - Connected Node
ID:   %s
ADDR: %s
==================================================
Options:
- PING <Unique ID prefix>
- PUT <filename>
- GET <KEY> <optional: filename>
- EXIT
- RT
- DS
--------------------------------------------------
`, kad.Me.ID.String(), kad.Me.Address)
}

// Truncates ID truncates the last- and first 4 characters
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

// trimPortFromAddress extracts the ip from the address
func trimPortFromAddress(address string) (string, error) {
	ip, _, ok := strings.Cut(address, ":")
	if !ok || ip == "" {
		return "", ErrIncorrectFormat
	}
	return ip, nil
}


// FindContact finds a specific given contact in a given contact list and responds with the contact 
func FindContactByAddress(contacts []kademlia.Contact, targetAddr string) (*kademlia.Contact, error) {
	for i := range contacts {
		if contacts[i].Address == targetAddr {
			return &contacts[i], nil
		}
	}
	return nil, ErrContactNotFound
}

// FindContactByID loops through a given contact list, if there's a match to the given IDprefix, the match is returned
func FindContactByID(contacts []kademlia.Contact, IDprefix string) (*kademlia.Contact, error) {

	prefix := strings.ToLower(strings.TrimSpace(IDprefix))
	var matched *kademlia.Contact
	matchCount := 0 
	
	for i := range contacts {

		// Check the prefix against the contact list 
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
			return nil, ErrAmbigousPrefix
		}

		return matched, nil
}

// GetLocalIP discovers the ip address of the docker container for this node.
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
