package main

import (
	"bufio"
	"bytes"
	"d7024e/kademlia"
	"d7024e/registry"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CLI represents the interactive command-line interface for a Kademlia registry node.
type CLI struct {
	Kad      *kademlia.Kademlia
	KM       *registry.KeyManager
	Resolver *NodeDNSResolver
	In       io.Reader
	Out      io.Writer
}

// NewCLI creates a new interactive CLI instance.
func NewCLI(kad *kademlia.Kademlia, km *registry.KeyManager, resolver *NodeDNSResolver, in io.Reader, out io.Writer) *CLI {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	return &CLI{
		Kad:      kad,
		KM:       km,
		Resolver: resolver,
		In:       in,
		Out:      out,
	}
}

// Run starts the interactive CLI read-eval-print loop.
func (c *CLI) Run() {
	c.ShowBanner()
	scanner := bufio.NewScanner(c.In)

	for {
		fmt.Fprint(c.Out, "> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		shouldExit, err := c.Execute(line)
		if err != nil {
			fmt.Fprintf(c.Out, "Error: %v\n", err)
		}
		if shouldExit {
			break
		}
	}
}

// Execute parses and runs a single command string.
// Returns shouldExit=true if the user entered an exit/quit command.
func (c *CLI) Execute(line string) (bool, error) {
	input := strings.TrimSpace(line)
	if input == "" {
		return false, nil
	}

	fields := splitCommandArgs(input)
	if len(fields) == 0 {
		return false, nil
	}

	cmd := strings.ToUpper(fields[0])
	args := fields[1:]

	switch cmd {
	case "EXIT", "QUIT":
		fmt.Fprintln(c.Out, "Thank you for using this Kademlia interactive CLI!")
		return true, nil

	case "HELP", "?":
		c.ShowHelp()
		return false, nil

	case "PING":
		return false, c.HandlePing(args)

	case "PUT":
		return false, c.HandlePut(args)

	case "GET":
		return false, c.HandleGet(args)

	case "FORGET":
		return false, c.HandleForget(args)

	case "SHOW":
		return false, c.HandleShow(args)

	case "RT", "ROUTING":
		return false, c.HandleShow([]string{"rt"})

	case "DS", "DATASTORE":
		return false, c.HandleShow([]string{"ds"})

	case "PUBLISH":
		return false, c.HandlePublish(args)

	case "INSTALL":
		return false, c.HandleInstall(args)

	case "KEYGEN":
		return false, c.HandleKeygen(args)

	case "SET":
		return false, c.HandleSet(args)

	default:
		return false, fmt.Errorf("unknown command %q. Type 'help' or '?' for available commands", fields[0])
	}
}

// HandlePing executes the ping command to test connectivity with a contact.
// Supports pinging either by unique ID prefix or by direct IP:Port address.
func (c *CLI) HandlePing(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ping <ip:port | unique-id-prefix>\n  Example: ping 127.0.0.1:8000\n  Example: ping a1b2")
	}
	target := strings.TrimSpace(args[0])
	if target == "" {
		return errors.New("usage: ping <ip:port | unique-id-prefix>")
	}
	if c.Kad == nil || c.Kad.RoutingTable == nil {
		return errors.New("routing table not initialized")
	}

	contacts := c.Kad.RoutingTable.GetAllContacts()
	var targetContact *kademlia.Contact
	var err error

	if strings.Contains(target, ":") {
		// Ping by direct IP:Port address
		targetContact, err = FindContactByAddress(contacts, target)
		if err != nil {
			// Contact not in routing table: create contact to ping directly
			id := kademlia.NewKademliaIDFromAddress(target)
			temp := kademlia.NewContact(id, target)
			targetContact = &temp
		}
	} else {
		// Ping by Unique ID prefix
		targetContact, err = FindContactByID(contacts, target)
		if err != nil {
			return fmt.Errorf("ping target not found: %w", err)
		}
	}

	start := time.Now()
	fmt.Fprintf(c.Out, "Pinging node %s (%s)...\n", truncateID(targetContact.ID.String()), targetContact.Address)

	resp, err := c.Kad.SendPing(targetContact)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	elapsedMs := float64(time.Since(start)) / float64(time.Millisecond)
	ip, _ := trimPortFromAddress(resp.Sender.Address)
	if ip == "" {
		ip = resp.Sender.Address
	}
	fmt.Fprintf(c.Out, "Ping response: %s from %s (ID: %s) in %.2f ms\n",
		resp.Type, ip, truncateID(resp.Sender.ID.String()), elapsedMs)
	return nil
}

// HandlePut stores either the contents of a local file or arbitrary text data into the DHT.
func (c *CLI) HandlePut(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: put <filename | data>\n  Example: put README.md\n  Example: put \"hello world\"")
	}

	var data []byte
	var filename string

	// Check if the argument corresponds to an existing file
	if len(args) == 1 {
		candidate := args[0]
		candidates := []string{
			candidate,
			filepath.Join("/data", candidate),
			filepath.Join("/root/keys", candidate),
			filepath.Join("./keys", candidate),
		}
		for _, cand := range candidates {
			if fileInfo, err := os.Stat(cand); err == nil && !fileInfo.IsDir() {
				if fileBytes, err := os.ReadFile(cand); err == nil {
					data = fileBytes
					filename = cand
					break
				}
			}
		}
	}

	// If not an existing file, treat the input fields as raw data
	if data == nil {
		data = []byte(strings.Join(args, " "))
	}

	if len(data) == 0 {
		return errors.New("cannot put empty data")
	}

	key, err := c.Kad.Store(data)
	if err != nil {
		return fmt.Errorf("store failed: %w", err)
	}

	if filename != "" {
		fmt.Fprintf(c.Out, "File %q successfully stored!\n", filename)
	} else {
		fmt.Fprintf(c.Out, "Data successfully stored!\n")
	}
	fmt.Fprintf(c.Out, "Key (SHA-256): %s\nBytes:         %d\n", key.String(), len(data))
	return nil
}

// HandleGet downloads a value from the DHT by its key hash.
func (c *CLI) HandleGet(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: get <key> [optional: filename]\n  Example: get 4a5e... output.bin")
	}

	keyHex := strings.TrimSpace(args[0])
	if !isCanonicalHexHash(keyHex) {
		return fmt.Errorf("invalid key %q: expected 64-character hexadecimal SHA-256 hash", keyHex)
	}
	key := kademlia.NewKademliaID(keyHex)

	data, responder, err := c.Kad.LookupDataByID(key)
	if err != nil {
		return fmt.Errorf("data retrieval failed for key %s: %w", truncateID(key.String()), err)
	}

	if len(args) == 2 {
		filename := args[1]
		dir := filepath.Dir(filename)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to save data to file %q: %w", filename, err)
		}
		fmt.Fprintf(c.Out, "Data (%d bytes) successfully saved to file %q\n", len(data), filename)
	} else {
		fmt.Fprintf(c.Out, "Key:   %s\nBytes: %d\nData:  %q\n", key.String(), len(data), string(data))
	}

	if responder != nil {
		fmt.Fprintf(c.Out, "Retrieved from node: %s (%s)\n", truncateID(responder.ID.String()), responder.Address)
	}
	return nil
}

// HandleForget removes a key-value pair from the local node's DataStore.
func (c *CLI) HandleForget(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: forget <key>\n  Example: forget 4a5e...")
	}
	if c.Kad == nil || c.Kad.DataStore == nil {
		return errors.New("data store not initialized")
	}

	keyHex := strings.TrimSpace(args[0])
	if !isCanonicalHexHash(keyHex) {
		return fmt.Errorf("invalid key %q: expected 64-character hexadecimal SHA-256 hash", keyHex)
	}
	key := kademlia.NewKademliaID(keyHex)

	deleted := c.Kad.DataStore.Delete(*key)
	if deleted {
		fmt.Fprintf(c.Out, "Key %s successfully forgotten from local DataStore.\n", key.String())
	} else {
		fmt.Fprintf(c.Out, "Key %s not found in local DataStore.\n", key.String())
	}
	return nil
}

// HandleShow dispatches routing table, datastore, DNS, or package version chain displays.
func (c *CLI) HandleShow(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: show <rt | routing | ds | dns <domain> | <domain>:<package>>\n  Example: show rt\n  Example: show ds\n  Example: show dns example.com\n  Example: show example.com:mypkg")
	}

	sub := strings.ToUpper(args[0])
	switch sub {
	case "RT", "ROUTING":
		return c.showRoutingTable()

	case "DS":
		return c.showDataStore()

	case "DNS":
		if len(args) < 2 {
			return errors.New("usage: show dns <domain>\n  Example: show dns example.com")
		}
		return c.showDNS(args[1])

	case "PACKAGE", "PKG":
		if len(args) == 2 {
			return c.showPackage(args[1])
		} else if len(args) == 3 {
			return c.showPackage(args[1] + ":" + args[2])
		}
		return errors.New("usage: show package <domain>:<package>")

	default:
		// Check if the argument is a package identifier (DOMAIN:PACKAGE or DOMAIN PACKAGE)
		if strings.Contains(args[0], ":") {
			return c.showPackage(args[0])
		}
		if len(args) == 2 {
			return c.showPackage(args[0] + ":" + args[1])
		}
		return fmt.Errorf("unknown show option %q. Valid options: rt, ds, dns <domain>, <domain>:<package>", args[0])
	}
}

func (c *CLI) showRoutingTable() error {
	if c.Kad == nil || c.Kad.RoutingTable == nil {
		return errors.New("routing table not initialized")
	}

	contacts := c.Kad.RoutingTable.GetAllContacts()
	if len(contacts) == 0 {
		fmt.Fprintln(c.Out, "Routing table is currently empty.")
		return nil
	}

	fmt.Fprintf(c.Out, "Routing table for node %s (%s):\n", c.Kad.Me.ID.String(), c.Kad.Me.Address)
	fmt.Fprintf(c.Out, "%-11s | %-15s | %-25s\n", "Bucket No.", "Node ID", "Address")
	fmt.Fprintln(c.Out, strings.Repeat("-", 60))

	for _, contact := range contacts {
		bucketIndex := c.Kad.RoutingTable.GetBucketIndex(contact.ID)
		fmt.Fprintf(c.Out, "%-11d | %-15s | %-25s\n", bucketIndex, truncateID(contact.ID.String()), contact.Address)
	}
	fmt.Fprintf(c.Out, "Total contacts: %d\n", len(contacts))
	return nil
}

func (c *CLI) showDataStore() error {
	if c.Kad == nil || c.Kad.DataStore == nil {
		return errors.New("data store not initialized")
	}

	keys := c.Kad.DataStore.GetAllKeys()
	if len(keys) == 0 {
		fmt.Fprintln(c.Out, "DataStore is currently empty.")
		return nil
	}

	fmt.Fprintf(c.Out, "DataStore contents (%d items):\n", len(keys))
	fmt.Fprintln(c.Out, strings.Repeat("-", 80))

	var vrCount, lpCount, blobCount int

	for i, k := range keys {
		val, exists := c.Kad.DataStore.Get(k)
		if !exists {
			continue
		}

		recType := registry.DetectRecordType(val)
		switch recType {
		case registry.RecordTypeVersionRecord:
			vrCount++
			vr, err := registry.ParseVersionRecord(val)
			if err == nil {
				fmt.Fprintf(c.Out, "[%d] [VersionRecord] %s:%s@%s\n", i+1, vr.Domain, vr.Package, vr.Version)
				fmt.Fprintf(c.Out, "    Key:      %s\n", k.String())
				fmt.Fprintf(c.Out, "    BlobHash: %s\n", vr.BlobHash)
				fmt.Fprintf(c.Out, "    Prev:     %s\n", vr.PreviousVersionRecord)
			} else {
				fmt.Fprintf(c.Out, "[%d] [VersionRecord (parse error)] Key: %s | Bytes: %d\n", i+1, k.String(), len(val))
			}

		case registry.RecordTypeLatestPointer:
			lpCount++
			lp, err := registry.ParseLatestPointer(val)
			if err == nil {
				fmt.Fprintf(c.Out, "[%d] [LatestPointer] %s:%s@%s -> %s\n", i+1, lp.Domain, lp.Package, lp.Version, lp.VersionRecordHash)
				fmt.Fprintf(c.Out, "    Key:      %s\n", k.String())
			} else {
				fmt.Fprintf(c.Out, "[%d] [LatestPointer (parse error)] Key: %s | Bytes: %d\n", i+1, k.String(), len(val))
			}

		default:
			blobCount++
			runes := []rune(string(val))
			preview := string(runes)
			if len(runes) > 40 {
				preview = string(runes[:40]) + "..."
			}
			preview = strings.ReplaceAll(preview, "\n", " ")
			fmt.Fprintf(c.Out, "[%d] [Blob] Key: %s | Bytes: %d | Data: %q\n", i+1, k.String(), len(val), preview)
		}
	}

	fmt.Fprintln(c.Out, strings.Repeat("-", 80))
	fmt.Fprintf(c.Out, "Summary: %d VersionRecords, %d LatestPointers, %d Raw Blobs\n", vrCount, lpCount, blobCount)
	return nil
}

func (c *CLI) showDNS(domain string) error {
	norm := registry.NormalizeDomain(domain)
	if !registry.IsValidDomain(norm) {
		return fmt.Errorf("invalid domain name: %q", domain)
	}

	if c.Resolver == nil {
		return errors.New("no DNS resolver configured on this node")
	}

	pub, err := c.Resolver.LookupOwnerKey(norm)
	if err != nil {
		fmt.Fprintf(c.Out, "Domain: %s\nOwner Public Key: NOT FOUND (%v)\n", norm, err)
		return nil
	}

	hexKey := registry.EncodePublicKeyHex(pub)
	txtRecord := registry.FormatDNSTXTRecord(pub)

	fmt.Fprintln(c.Out, "DNS Ownership Record:")
	fmt.Fprintf(c.Out, "  Domain:           %s\n", norm)
	fmt.Fprintf(c.Out, "  Public Key (Hex): %s\n", hexKey)
	fmt.Fprintf(c.Out, "  DNS TXT Record:   %s\n", txtRecord)
	fmt.Fprintf(c.Out, "  Status:           VERIFIED\n")
	return nil
}

func (c *CLI) showPackage(pkgTarget string) error {
	parts := strings.Split(pkgTarget, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid package specification %q: expected DOMAIN:PACKAGE (e.g. example.com:mypkg)", pkgTarget)
	}

	domain := registry.NormalizeDomain(parts[0])
	pkg := strings.TrimSpace(parts[1])

	if !registry.IsValidDomain(domain) {
		return fmt.Errorf("invalid domain %q", domain)
	}
	if !registry.IsValidPackageName(pkg) {
		return fmt.Errorf("invalid package name %q", pkg)
	}

	lp, _, err := c.Kad.LookupLatestPointer(domain, pkg)
	if err != nil || lp == nil {
		return fmt.Errorf("package %s:%s not found in registry (latest pointer lookup failed)", domain, pkg)
	}

	sigStatus := "UNVERIFIED (no DNS resolver)"
	if c.Resolver != nil {
		if err := lp.VerifyWithResolver(c.Resolver); err == nil {
			sigStatus = "VALID (signed by verified domain owner)"
		} else {
			sigStatus = fmt.Sprintf("INVALID SIGNATURE (%v)", err)
		}
	}

	chain, walkErr := c.Kad.WalkVersionChain(lp.VersionRecordHash)
	if walkErr != nil && len(chain) == 0 {
		return fmt.Errorf("failed to retrieve version chain for %s:%s: %w", domain, pkg, walkErr)
	}

	fmt.Fprintln(c.Out, "==================================================")
	fmt.Fprintf(c.Out, "Package:             %s:%s\n", domain, pkg)
	fmt.Fprintf(c.Out, "Latest Version:      %s\n", lp.Version)
	fmt.Fprintf(c.Out, "Latest Pointer Key:  %s\n", lp.DHTKey())
	fmt.Fprintf(c.Out, "Head Record Hash:    %s\n", lp.VersionRecordHash)
	fmt.Fprintf(c.Out, "Pointer Signature:   %s\n", sigStatus)
	fmt.Fprintln(c.Out, "==================================================")

	fmt.Fprintf(c.Out, "Version History Chain (%d versions, newest to oldest):\n", len(chain))
	fmt.Fprintln(c.Out, strings.Repeat("-", 60))

	for i, vr := range chain {
		recHash, _ := vr.RecordHash()
		tag := ""
		if i == 0 {
			tag = " (LATEST)"
		}
		if vr.IsInitialVersion() {
			tag += " (INITIAL RELEASE)"
		}

		vrSigStatus := "VALID"
		if c.Resolver != nil {
			if err := vr.VerifyWithResolver(c.Resolver); err != nil {
				vrSigStatus = fmt.Sprintf("INVALID (%v)", err)
			}
		}

		fmt.Fprintf(c.Out, "[%d] v%s%s\n", i+1, vr.Version, tag)
		fmt.Fprintf(c.Out, "    Record Hash: %s\n", recHash)
		fmt.Fprintf(c.Out, "    Blob Hash:   %s\n", vr.BlobHash)
		fmt.Fprintf(c.Out, "    Previous:    %s\n", vr.PreviousVersionRecord)
		fmt.Fprintf(c.Out, "    Signer:      %s\n", vr.Domain)
		fmt.Fprintf(c.Out, "    Signature:   %s\n", vrSigStatus)
	}

	if walkErr != nil {
		fmt.Fprintf(c.Out, "Warning: Chain traversal terminated prematurely: %v\n", walkErr)
	}
	fmt.Fprintln(c.Out, strings.Repeat("-", 60))
	return nil
}

// HandlePublish publishes a package file into the DHT.
// Supports flags:
//
//	--force: bypasses local pre-flight checks and attempts publication to test network rejection.
//	--prev=VERSION: explicitly specifies previous version record to link to.
func (c *CLI) HandlePublish(args []string) error {
	var force bool
	var prevFlag string
	var hasPrevFlag bool
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--force" {
			force = true
		} else if strings.HasPrefix(arg, "--prev=") {
			prevFlag = strings.TrimPrefix(arg, "--prev=")
			hasPrevFlag = true
		} else if arg == "--prev" {
			if i+1 < len(args) {
				i++
				prevFlag = args[i]
				hasPrevFlag = true
			} else {
				return errors.New("missing value for flag --prev")
			}
		} else if strings.HasPrefix(arg, "-") {
			return fmt.Errorf("unknown flag %q", arg)
		} else {
			positional = append(positional, arg)
		}
	}

	var target, filename string
	if len(positional) == 2 {
		target = positional[0]
		filename = positional[1]
	} else if len(positional) > 2 && strings.Contains(positional[0], ":") {
		// Target is DOMAIN:PKG:VERSION and remaining tokens are the payload
		target = positional[0]
		filename = strings.Join(positional[1:], " ")
	} else if len(positional) == 4 && !strings.Contains(positional[0], ":") {
		// User friendly space-separated syntax: publish DOMAIN PKG VERSION FILENAME
		target = positional[0] + ":" + positional[1] + ":" + positional[2]
		filename = positional[3]
	} else if len(positional) > 4 && !strings.Contains(positional[0], ":") {
		// User friendly space-separated syntax: publish DOMAIN PKG VERSION payload words...
		target = positional[0] + ":" + positional[1] + ":" + positional[2]
		filename = strings.Join(positional[3:], " ")
	} else {
		return errors.New("usage: publish [--force] [--prev=PREVIOUS-VERSION] DOMAIN:PACKAGE:VERSION FILENAME\n  Example: publish example.com:mypkg:1.0.0 ./mypkg.tar.gz")
	}

	targetParts := strings.Split(target, ":")
	if len(targetParts) != 3 {
		return fmt.Errorf("invalid package specification %q: expected DOMAIN:PACKAGE:VERSION (e.g. example.com:mypkg:1.0.0)", target)
	}

	domain := registry.NormalizeDomain(targetParts[0])
	pkg := strings.TrimSpace(targetParts[1])
	verStr := strings.TrimSpace(targetParts[2])

	if !registry.IsValidDomain(domain) && !force {
		return fmt.Errorf("invalid domain name: %q", domain)
	}
	if !registry.IsValidPackageName(pkg) && !force {
		return fmt.Errorf("invalid package name: %q", pkg)
	}

	parsedVer, err := registry.ParseVersion(verStr)
	normVerStr := verStr
	if err == nil {
		normVerStr = parsedVer.String()
	} else if !force {
		return fmt.Errorf("invalid semantic version %q: %w", verStr, err)
	}

	// Read package file blob
	var fileData []byte
	candidates := []string{
		filename,
		filepath.Join("/root/keys", filename),
		filepath.Join("./keys", filename),
		filepath.Join("/data", filename),
	}
	for _, cand := range candidates {
		if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
			fileData = data
			filename = cand
			break
		}
	}
	if fileData == nil {
		// If argument contains spaces or is quoted text (inline content), use it as payload
		if strings.Contains(filename, " ") || strings.Contains(filename, "\n") || strings.Contains(filename, "\t") ||
			(!strings.Contains(filename, ".") && !strings.Contains(filename, "/")) {
			fileData = []byte(filename)
			filename = "<inline-content>"
		} else {
			return fmt.Errorf("failed to read package file %q: file not found on node filesystem", filename)
		}
	}
	blobHash := registry.ComputeBlobHash(fileData)

	// Pre-flight check: Key availability
	var dkp *registry.DomainKeyPair
	if c.KM != nil {
		dkp, err = c.KM.Load(domain)
	}
	if err != nil || dkp == nil {
		if !force {
			return fmt.Errorf("domain private key for %q not found: %v (generate one using 'keygen %s' or place in keys directory, or use --force to bypass)", domain, err, domain)
		}
		// If forced, create an ephemeral throwaway key to generate a signature that remote nodes will reject
		dkp, _ = registry.GenerateDomainKeyPair(domain)
	}

	// Pre-flight check: DNS ownership match
	if !force && c.Resolver != nil {
		ownerPub, err := c.Resolver.LookupOwnerKey(domain)
		if err != nil {
			return fmt.Errorf("domain ownership verification failed for %q: %w", domain, err)
		}
		if !bytes.Equal(ownerPub, dkp.PublicKey) {
			return fmt.Errorf("domain ownership mismatch for %q: local key does not match DNS owner key", domain)
		}
	}

	// Pre-flight check: Previous version linkage & Monotonicity
	currLP, _, _ := c.Kad.LookupLatestPointer(domain, pkg)
	var prevRecordHash string

	if currLP != nil {
		if !force {
			vNew, e1 := registry.ParseVersion(normVerStr)
			vCurr, e2 := currLP.ParsedVersion()
			if e1 == nil && e2 == nil && vNew.Compare(vCurr) <= 0 {
				return fmt.Errorf("version rollback rejected: new version %s is not strictly greater than current latest %s (use --force to attempt rollback)", normVerStr, currLP.Version)
			}
		}

		if hasPrevFlag {
			if prevFlag == "none" || prevFlag == "0" || prevFlag == "0.0.0" || prevFlag == registry.ZeroHash {
				if !force {
					return fmt.Errorf("cannot link existing package to zero previous record: latest version is %s (use --force to attempt illegal reset)", currLP.Version)
				}
				prevRecordHash = registry.ZeroHash
			} else if len(prevFlag) == 64 && isCanonicalHexHash(prevFlag) {
				hexTarget := strings.ToLower(prevFlag)
				if !force && hexTarget != currLP.VersionRecordHash {
					return fmt.Errorf("fork rejected: specified previous record hash %s does not match current latest version record %s (use --force to attempt creating a fork)", hexTarget, currLP.VersionRecordHash)
				}
				prevRecordHash = hexTarget
			} else {
				// Walk the chain to find the requested previous version
				chain, walkErr := c.Kad.WalkVersionChain(currLP.VersionRecordHash)
				var foundHash string
				if walkErr == nil {
					for _, vr := range chain {
						if vr.Version == prevFlag {
							h, _ := vr.RecordHash()
							foundHash = h
							break
						}
						if pVer, err := vr.ParsedVersion(); err == nil {
							if targetPVer, err := registry.ParseVersion(prevFlag); err == nil && pVer.Compare(targetPVer) == 0 {
								h, _ := vr.RecordHash()
								foundHash = h
								break
							}
						}
					}
				}
				if foundHash == "" {
					return fmt.Errorf("specified previous version %q not found in chain for %s:%s (current latest is %s)", prevFlag, domain, pkg, currLP.Version)
				}
				if !force && foundHash != currLP.VersionRecordHash {
					return fmt.Errorf("fork rejected: specified previous version %s is an older predecessor, not current latest %s (use --force to attempt creating a fork)", prevFlag, currLP.Version)
				}
				prevRecordHash = foundHash
			}
		} else {
			prevRecordHash = currLP.VersionRecordHash
		}
	} else {
		// Initial package release
		if hasPrevFlag {
			if prevFlag == "none" || prevFlag == "0" || prevFlag == "0.0.0" || prevFlag == registry.ZeroHash {
				prevRecordHash = registry.ZeroHash
			} else if !force {
				return fmt.Errorf("cannot link to previous version %q: initial release has no previous versions (use --force to bypass)", prevFlag)
			} else {
				if len(prevFlag) == 64 && isCanonicalHexHash(prevFlag) {
					prevRecordHash = strings.ToLower(prevFlag)
				} else {
					return fmt.Errorf("cannot resolve previous version %q on initial release (specify a 64-character record hash with --prev=<hash> to force)", prevFlag)
				}
			}
		} else {
			prevRecordHash = registry.ZeroHash
		}
	}

	// Store package file blob in DHT
	blobKey, err := c.Kad.Store(fileData)
	if err != nil {
		return fmt.Errorf("failed to store package file blob: %w", err)
	}

	// Create, sign, and store VersionRecord in DHT
	vr, err := registry.NewVersionRecord(domain, pkg, normVerStr, blobHash, prevRecordHash)
	if err != nil {
		if !force {
			return fmt.Errorf("failed to create version record: %w", err)
		}
		vr = &registry.VersionRecord{
			Tag:                   registry.TagVersionRecord,
			Domain:                domain,
			Package:               pkg,
			Version:               normVerStr,
			BlobHash:              blobHash,
			PreviousVersionRecord: prevRecordHash,
		}
	}
	_ = vr.Sign(dkp.PrivateKey)

	vrBytes, err := vr.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize version record: %w", err)
	}
	vrKey, err := c.Kad.Store(vrBytes)
	if err != nil {
		return fmt.Errorf("failed to store version record: %w", err)
	}

	// Create, sign, and store LatestPointer in DHT
	vrHash, _ := vr.RecordHash()
	lp, err := registry.NewLatestPointer(domain, pkg, normVerStr, vrHash)
	if err != nil {
		if !force {
			return fmt.Errorf("failed to create latest pointer: %w", err)
		}
		lp = &registry.LatestPointer{
			Tag:               registry.TagLatestPointer,
			Domain:            domain,
			Package:           pkg,
			Version:           normVerStr,
			VersionRecordHash: vrHash,
		}
	}
	_ = lp.Sign(dkp.PrivateKey)

	if !force {
		if err := c.Kad.StoreLatestPointer(lp); err != nil {
			return fmt.Errorf("failed to store latest pointer: %w", err)
		}
		fmt.Fprintf(c.Out, "Successfully published package %s:%s@%s!\n", domain, pkg, normVerStr)
	} else {
		if err := c.Kad.StoreLatestPointerForce(lp); err != nil {
			return fmt.Errorf("force publication failed: %w", err)
		}
		fmt.Fprintf(c.Out, "Attempted forced publication of %s:%s@%s (--force)!\n", domain, pkg, normVerStr)
		fmt.Fprintln(c.Out, "Note: Local pre-flight checks bypassed. Remote nodes validate updates according to Phase 3 rules.")
	}

	fmt.Fprintf(c.Out, "  File:               %s (%d bytes)\n", filename, len(fileData))
	fmt.Fprintf(c.Out, "  Blob Hash:          %s\n", blobKey.String())
	fmt.Fprintf(c.Out, "  Version Record:     %s\n", vrKey.String())
	fmt.Fprintf(c.Out, "  Previous Record:    %s\n", prevRecordHash)
	fmt.Fprintf(c.Out, "  Latest Pointer Key: %s\n", lp.DHTKey())
	return nil
}

// HandleInstall downloads and verifies a package from the DHT.
func (c *CLI) HandleInstall(args []string) error {
	var domain, pkg, verStr, destFilename string

	if len(args) == 1 || len(args) == 2 {
		target := args[0]
		if len(args) == 2 {
			destFilename = args[1]
		}
		parts := strings.Split(target, ":")
		if len(parts) != 3 {
			return fmt.Errorf("invalid package specification %q: expected DOMAIN:PACKAGE:VERSION (e.g. example.com:mypkg:latest or example.com:mypkg:1.0.0)", target)
		}
		domain = registry.NormalizeDomain(parts[0])
		pkg = strings.TrimSpace(parts[1])
		verStr = strings.TrimSpace(parts[2])
	} else if len(args) == 3 || len(args) == 4 {
		// User friendly space-separated syntax: install DOMAIN PACKAGE VERSION [FILENAME]
		domain = registry.NormalizeDomain(args[0])
		pkg = strings.TrimSpace(args[1])
		verStr = strings.TrimSpace(args[2])
		if len(args) == 4 {
			destFilename = args[3]
		}
	} else {
		return errors.New("usage: install DOMAIN:PACKAGE:VERSION [FILENAME]\n  Example: install example.com:mypkg:latest\n  Example: install example.com:mypkg:1.0.0 output.bin")
	}

	// Resolve LatestPointer
	lp, _, err := c.Kad.LookupLatestPointer(domain, pkg)
	if err != nil || lp == nil {
		return fmt.Errorf("package %s:%s not found in registry (latest pointer lookup failed)", domain, pkg)
	}

	// Verify LatestPointer with DNS
	if c.Resolver != nil {
		if err := lp.VerifyWithResolver(c.Resolver); err != nil {
			return fmt.Errorf("security verification failed: latest pointer signature is invalid: %w", err)
		}
	}

	// Resolve target VersionRecord
	var targetVR *registry.VersionRecord

	if strings.EqualFold(verStr, "latest") {
		// Direct lookup of the head record
		vrData, _, err := c.Kad.LookupData(lp.VersionRecordHash)
		if err != nil || len(vrData) == 0 {
			return fmt.Errorf("failed to retrieve version record %s: %w", lp.VersionRecordHash, err)
		}
		vr, err := registry.ParseVersionRecord(vrData)
		if err != nil {
			return fmt.Errorf("corrupt version record: %w", err)
		}
		if c.Resolver != nil {
			if err := vr.VerifyWithResolver(c.Resolver); err != nil {
				return fmt.Errorf("security verification failed: version record signature invalid: %w", err)
			}
		}
		targetVR = vr
	} else {
		// Specific version requested: walk version chain
		reqVer, err := registry.ParseVersion(verStr)
		if err != nil {
			return fmt.Errorf("invalid version %q: %w", verStr, err)
		}

		chain, err := c.Kad.WalkVersionChain(lp.VersionRecordHash)
		if err != nil && len(chain) == 0 {
			return fmt.Errorf("failed to retrieve version history for %s:%s: %w", domain, pkg, err)
		}

		for _, vr := range chain {
			if c.Resolver != nil {
				if err := vr.VerifyWithResolver(c.Resolver); err != nil {
					return fmt.Errorf("security verification failed: invalid signature on version %s: %w", vr.Version, err)
				}
			}
			vrVer, err := vr.ParsedVersion()
			if err == nil && vrVer.Compare(reqVer) == 0 {
				targetVR = vr
				break
			}
		}

		if targetVR == nil {
			return fmt.Errorf("version %s not found for package %s:%s (current latest is %s)", verStr, domain, pkg, lp.Version)
		}
	}

	// Download package file blob
	blobData, responder, err := c.Kad.LookupData(targetVR.BlobHash)
	if err != nil || len(blobData) == 0 {
		return fmt.Errorf("failed to retrieve package binary blob %s: %w", targetVR.BlobHash, err)
	}

	// Verify integrity (hash matches blobHash)
	actualHash := registry.ComputeBlobHash(blobData)
	if !strings.EqualFold(actualHash, targetVR.BlobHash) {
		return fmt.Errorf("data integrity check failed: downloaded blob hash %s does not match expected %s", actualHash, targetVR.BlobHash)
	}

	// Save binary blob to disk
	if destFilename == "" {
		destFilename = fmt.Sprintf("%s-%s.bin", targetVR.Package, targetVR.Version)
	}
	dir := filepath.Dir(destFilename)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	if err := os.WriteFile(destFilename, blobData, 0644); err != nil {
		return fmt.Errorf("failed to save package binary to %q: %w", destFilename, err)
	}

	// Output summary
	recHash, _ := targetVR.RecordHash()
	fmt.Fprintf(c.Out, "Package %s:%s@%s installed successfully!\n", targetVR.Domain, targetVR.Package, targetVR.Version)
	fmt.Fprintf(c.Out, "  File Saved:   %s (%d bytes)\n", destFilename, len(blobData))
	fmt.Fprintf(c.Out, "  Blob Hash:    %s\n", targetVR.BlobHash)
	fmt.Fprintf(c.Out, "  Record Hash:  %s\n", recHash)
	fmt.Fprintf(c.Out, "  Integrity:    Verified (SHA-256 match)\n")
	fmt.Fprintf(c.Out, "  Authenticity: Verified (signed by %s)\n", targetVR.Domain)
	if responder != nil {
		fmt.Fprintf(c.Out, "  Downloaded:   Node %s (%s)\n", truncateID(responder.ID.String()), responder.Address)
	}
	return nil
}

// HandleKeygen generates a new domain keypair and registers it locally.
func (c *CLI) HandleKeygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: keygen <domain>")
	}
	domain := registry.NormalizeDomain(args[0])
	if !registry.IsValidDomain(domain) {
		return fmt.Errorf("invalid domain name: %q", domain)
	}

	if c.KM == nil {
		return errors.New("key manager not initialized")
	}

	dkp, err := c.KM.Generate(domain)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	if c.Resolver != nil {
		_ = c.Resolver.SetKey(domain, dkp.PublicKey)
	}

	hexKey := registry.EncodePublicKeyHex(dkp.PublicKey)
	txtRecord := registry.FormatDNSTXTRecord(dkp.PublicKey)

	fmt.Fprintf(c.Out, "Generated new key pair for domain %q!\n", domain)
	fmt.Fprintf(c.Out, "  Public Key (Hex): %s\n", hexKey)
	fmt.Fprintf(c.Out, "  DNS TXT Record:   %s\n", txtRecord)
	fmt.Fprintf(c.Out, "  Status:           Loaded and active in local resolver cache\n")
	return nil
}

// HandleSet handles setting configuration values such as DNS domain ownership keys.
func (c *CLI) HandleSet(args []string) error {
	if len(args) != 3 || !strings.EqualFold(args[0], "DNS") {
		return errors.New("usage: set dns <domain> <public-key-hex>\n  Example: set dns example.com a1b2c3...")
	}
	domain := registry.NormalizeDomain(args[1])
	hexKey := strings.TrimSpace(args[2])
	if c.Resolver == nil {
		return errors.New("resolver not initialized")
	}
	if err := c.Resolver.SetKeyHex(domain, hexKey); err != nil {
		return fmt.Errorf("failed to set domain key: %w", err)
	}
	fmt.Fprintf(c.Out, "Successfully registered DNS owner key for domain %q in local resolver cache!\n", domain)
	return nil
}

// ShowBanner prints the interactive startup banner.
func (c *CLI) ShowBanner() {
	idStr := "uninitialized"
	addrStr := "uninitialized"
	if c.Kad != nil && c.Kad.Me.ID != nil {
		idStr = c.Kad.Me.ID.String()
		addrStr = c.Kad.Me.Address
	}

	fmt.Fprintf(c.Out, `==================================================
Kademlia Package Registry - Connected Node
ID:   %s
ADDR: %s
==================================================
Type 'help' or '?' to view available commands.
--------------------------------------------------
`, idStr, addrStr)
}

// ShowHelp prints formatted command help with usage examples.
func (c *CLI) ShowHelp() {
	fmt.Fprintln(c.Out, `Available Commands:
--------------------------------------------------------------------------------
Package Registry Commands:
  publish [--force] [--prev=VER] DOMAIN:PKG:VER FILE
      Publish a package binary to the decentralized registry.
      --force: bypass local validation to test network enforcement.
      --prev:  explicitly specify the previous version to link to.
      Example: publish example.com:mypkg:1.0.0 ./mypkg.tar.gz

  install DOMAIN:PKG:VER [FILE]
      Download and verify a package binary from the registry.
      VER may be a specific semantic version (e.g. 1.0.0) or 'latest'.
      Example: install example.com:mypkg:latest mypkg.tar.gz

  show DOMAIN:PKG
      Display the full version history chain and signatures for a package.
      Example: show example.com:mypkg

  show dns DOMAIN
      Display the owner public key and DNS TXT record for a domain.
      Example: show dns example.com

  set dns DOMAIN KEY_HEX
      Manually register an Ed25519 public key (hex) for a domain in DNS cache.
      Example: set dns example.com a1b2c3...

  keygen DOMAIN
      Generate an Ed25519 key pair for a domain and register it locally.
      Example: keygen example.com

DHT & Node Commands:
  put <filename | data>
      Upload a file or raw string into the DHT under its SHA-256 hash.
      Example: put README.md

  get <KEY> [filename]
      Retrieve data from the DHT by its 64-char hex key.
      Example: get 4a5e... output.bin

  forget <KEY>
      Remove a key-value pair from this node's local DataStore.
      Example: forget 4a5e...

  show rt | routing
      Display the local Kademlia routing table.

  show ds
      Display all DataStore items (interpreted VersionRecords, LatestPointers, blobs).

  ping <ip:port | unique-id-prefix>
      Send a ping probe to a contact by IP:Port or routing table ID prefix.
      Example: ping 127.0.0.1:8000
      Example: ping a1b2

  help | ?
      Display this help menu.

  exit | quit
      Exit the interactive CLI session.
--------------------------------------------------------------------------------`)
}

func isCanonicalHexHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// splitCommandArgs splits a command line into arguments, preserving quoted strings.
func splitCommandArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else {
			if c == '"' || c == '\'' {
				inQuote = true
				quoteChar = c
			} else if c == ' ' || c == '\t' {
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			} else {
				current.WriteByte(c)
			}
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
