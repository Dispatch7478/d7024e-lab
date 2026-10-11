package main

import (
	"d7024e/kademlia"
	"d7024e/registry"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lmittmann/tint"
)

var (
	ErrContactNotFound = errors.New("contact not found")
	ErrAmbigousPrefix  = errors.New("ambigous prefix: multiple contacts matched")
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
	var handler slog.Handler = tint.NewHandler(os.Stderr, &tint.Options{
		Level:      logLevel,
		TimeFormat: time.TimeOnly,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if (a.Key == "target" || a.Key == "key" || a.Key == "from_id") && a.Value.Kind() == slog.KindString {
				return slog.String(a.Key, truncateID(a.Value.String()))
			}
			return a
		},
	})
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

	keysDir := getEnv("KEYS_DIR", "./keys")
	kad, network, km, dnsResolver, err := createNode(localIP, ip, port, keysDir)
	if err != nil {
		slog.Error("failed to listen", "err", err)
		os.Exit(1)
	}
	defer network.Close()

	slog.Info("Starting node", "address", kad.Me.Address, "id", kad.Me.ID.String())

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

	runCLI(kad, km, dnsResolver)
}

// createNode initializes a Kademlia node with UDP network, DataStore, KeyManager, and DNS resolver.
func createNode(localIP, ip string, port int, keysDir string) (*kademlia.Kademlia, *kademlia.UDPNetwork, *registry.KeyManager, *NodeDNSResolver, error) {
	listenAddr := fmt.Sprintf("%s:%d", localIP, port)
	id := kademlia.NewKademliaIDFromAddress(listenAddr)
	me := kademlia.NewContact(id, listenAddr)

	rt := kademlia.NewRoutingTable(me)
	ds := kademlia.NewDataStore()
	network := kademlia.NewUDPNetwork(me, rt, ds)
	if err := network.Listen(ip, port); err != nil {
		return nil, nil, nil, nil, err
	}

	kad := kademlia.NewKademlia(me, network, rt, ds, 0)

	km, err := registry.NewKeyManager(keysDir)
	if err != nil {
		slog.Warn("Failed to initialize file key manager, using memory", "err", err)
		km, _ = registry.NewKeyManager("")
	}

	dnsResolver := NewNodeDNSResolver()
	if km != nil {
		dnsResolver.SetKeyManager(km)
		for _, domain := range km.ListDomains() {
			if dkp, err := km.Load(domain); err == nil && dkp != nil {
				_ = dnsResolver.SetKey(domain, dkp.PublicKey)
			}
		}
	}
	kad.SetDNSResolver(dnsResolver)

	return kad, network, km, dnsResolver, nil
}

// runCLI runs the interactive CLI session.
func runCLI(kad *kademlia.Kademlia, km *registry.KeyManager, resolver *NodeDNSResolver) {
	runCLIWithIO(kad, km, resolver, os.Stdin, os.Stdout)
}

// runCLIWithIO runs the interactive CLI session with custom IO.
func runCLIWithIO(kad *kademlia.Kademlia, km *registry.KeyManager, resolver *NodeDNSResolver, in io.Reader, out io.Writer) {
	cli := NewCLI(kad, km, resolver, in, out)
	cli.Run()
}

// =================
// HELPER FUNCTIONS
// =================

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
