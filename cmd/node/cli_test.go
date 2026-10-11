package main

import (
	"bytes"
	"crypto/ed25519"
	"d7024e/kademlia"
	"d7024e/registry"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupTestCLI(t *testing.T) (*CLI, *kademlia.Kademlia, *registry.KeyManager, *NodeDNSResolver, *bytes.Buffer) {
	t.Helper()
	tempDir := t.TempDir()

	hub := kademlia.NewSimulatedHub()
	idA := kademlia.NewKademliaID("1000000000000000000000000000000000000000000000000000000000000001")
	meA := kademlia.NewContact(idA, "sim:node1")
	rtA := kademlia.NewRoutingTable(meA)
	dsA := kademlia.NewDataStore()
	netA := kademlia.NewSimulatedNetwork(meA, rtA, hub, dsA)
	kad := kademlia.NewKademlia(meA, netA, rtA, dsA, 3)

	km, err := registry.NewKeyManager(filepath.Join(tempDir, "keys"))
	if err != nil {
		t.Fatalf("failed to create KeyManager: %v", err)
	}

	resolver := NewNodeDNSResolver()
	kad.SetDNSResolver(resolver)

	out := &bytes.Buffer{}
	cli := NewCLI(kad, km, resolver, strings.NewReader(""), out)
	return cli, kad, km, resolver, out
}

func TestCLI_Help_And_Banner(t *testing.T) {
	cli, _, _, _, out := setupTestCLI(t)

	// ShowBanner
	cli.ShowBanner()
	bannerOutput := out.String()
	if !strings.Contains(bannerOutput, "Kademlia Package Registry") {
		t.Errorf("expected banner to mention Kademlia Package Registry, got: %s", bannerOutput)
	}
	out.Reset()

	// ShowHelp
	cli.ShowHelp()
	helpOutput := out.String()
	requiredCmds := []string{"publish", "install", "show", "ping", "put", "get", "forget", "keygen", "exit"}
	for _, cmd := range requiredCmds {
		if !strings.Contains(helpOutput, cmd) {
			t.Errorf("expected help output to mention command %q", cmd)
		}
	}
	out.Reset()

	// Execute "help" and "?"
	exit, err := cli.Execute("help")
	if err != nil || exit {
		t.Errorf("execute help failed: exit=%v, err=%v", exit, err)
	}
	out.Reset()

	exit, err = cli.Execute("?")
	if err != nil || exit {
		t.Errorf("execute ? failed: exit=%v, err=%v", exit, err)
	}
}

func TestCLI_Exit_And_UnknownCommand(t *testing.T) {
	cli, _, _, _, out := setupTestCLI(t)

	// Empty input
	exit, err := cli.Execute("   ")
	if err != nil || exit {
		t.Errorf("expected false/nil for empty line, got exit=%v, err=%v", exit, err)
	}

	// Exit
	exit, err = cli.Execute("exit")
	if err != nil || !exit {
		t.Errorf("expected true/nil for exit, got exit=%v, err=%v", exit, err)
	}

	// Quit
	exit, err = cli.Execute("quit")
	if err != nil || !exit {
		t.Errorf("expected true/nil for quit, got exit=%v, err=%v", exit, err)
	}

	// Unknown command
	exit, err = cli.Execute("nonexistent_command foo bar")
	if err == nil || exit {
		t.Errorf("expected error for unknown command, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("expected unknown command error message, got: %v", err)
	}
	_ = out
}

func TestCLI_Ping(t *testing.T) {
	tempDir := t.TempDir()
	hub := kademlia.NewSimulatedHub()

	// Node 1 (CLI node)
	idA := kademlia.NewKademliaID("1000000000000000000000000000000000000000000000000000000000000001")
	meA := kademlia.NewContact(idA, "127.0.0.1:8001")
	rtA := kademlia.NewRoutingTable(meA)
	dsA := kademlia.NewDataStore()
	netA := kademlia.NewSimulatedNetwork(meA, rtA, hub, dsA)
	kadA := kademlia.NewKademlia(meA, netA, rtA, dsA, 3)

	// Node 2 (Peer node)
	idB := kademlia.NewKademliaID("2000000000000000000000000000000000000000000000000000000000000002")
	meB := kademlia.NewContact(idB, "127.0.0.1:8002")
	rtB := kademlia.NewRoutingTable(meB)
	dsB := kademlia.NewDataStore()
	_ = kademlia.NewSimulatedNetwork(meB, rtB, hub, dsB)

	km, _ := registry.NewKeyManager(filepath.Join(tempDir, "keys"))
	resolver := NewNodeDNSResolver()
	kadA.SetDNSResolver(resolver)

	out := &bytes.Buffer{}
	cli := NewCLI(kadA, km, resolver, strings.NewReader(""), out)

	// Wrong arg count
	if err := cli.HandlePing([]string{}); err == nil {
		t.Errorf("expected error for missing ping arg")
	}
	if err := cli.HandlePing([]string{"a", "b"}); err == nil {
		t.Errorf("expected error for extra ping args")
	}

	// Ping by ID prefix when contact not found
	err := cli.HandlePing([]string{"abcd"})
	if err == nil || !strings.Contains(err.Error(), "ping target not found") {
		t.Errorf("expected contact not found error, got: %v", err)
	}

	// Ping by direct IP:Port address (contact not yet in routing table)
	out.Reset()
	err = cli.HandlePing([]string{"127.0.0.1:8002"})
	if err != nil {
		t.Fatalf("ping by IP:Port address failed: %v", err)
	}
	pingOut := out.String()
	if !strings.Contains(pingOut, "Ping response:") || !strings.Contains(pingOut, "127.0.0.1") {
		t.Errorf("expected successful ping response output, got: %s", pingOut)
	}

	// Ping by unique ID prefix after adding to routing table
	kadA.RoutingTable.AddContact(meB)
	out.Reset()
	err = cli.HandlePing([]string{"2000"})
	if err != nil {
		t.Fatalf("ping by unique ID prefix failed: %v", err)
	}
	if !strings.Contains(out.String(), "Ping response:") {
		t.Errorf("expected successful ping response by ID prefix, got: %s", out.String())
	}

	// Ping unreachable node
	err = cli.HandlePing([]string{"127.0.0.1:9999"})
	if err == nil {
		t.Errorf("expected error pinging unreachable address")
	}
}

func TestCLI_Put_Get_Forget(t *testing.T) {
	cli, kad, _, _, out := setupTestCLI(t)
	tempDir := t.TempDir()

	// Put raw string data
	out.Reset()
	err := cli.HandlePut([]string{"hello", "world"})
	if err != nil {
		t.Fatalf("put raw data failed: %v", err)
	}
	putOutput := out.String()
	if !strings.Contains(putOutput, "Data successfully stored") {
		t.Errorf("expected success message, got: %s", putOutput)
	}

	// Put file data
	testFile := filepath.Join(tempDir, "sample.txt")
	if err := os.WriteFile(testFile, []byte("file content payload"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	out.Reset()
	err = cli.HandlePut([]string{testFile})
	if err != nil {
		t.Fatalf("put file failed: %v", err)
	}
	if !strings.Contains(out.String(), "successfully stored") {
		t.Errorf("expected file stored message, got: %s", out.String())
	}

	// Put error cases
	if err := cli.HandlePut([]string{}); err == nil {
		t.Errorf("expected error for empty put args")
	}

	// Get data by key
	dataKey := kademlia.NewKademliaIDFromData([]byte("file content payload"))
	out.Reset()
	err = cli.HandleGet([]string{dataKey.String()})
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if !strings.Contains(out.String(), "file content payload") {
		t.Errorf("expected data in get output, got: %s", out.String())
	}

	// Get and save to file
	destFile := filepath.Join(tempDir, "downloaded.txt")
	out.Reset()
	err = cli.HandleGet([]string{dataKey.String(), destFile})
	if err != nil {
		t.Fatalf("get with file failed: %v", err)
	}
	content, err := os.ReadFile(destFile)
	if err != nil || string(content) != "file content payload" {
		t.Errorf("saved content mismatch: %q, err: %v", string(content), err)
	}

	// Get invalid keys / missing
	if err := cli.HandleGet([]string{}); err == nil {
		t.Errorf("expected error for missing get args")
	}
	if err := cli.HandleGet([]string{"bad", "bad", "bad"}); err == nil {
		t.Errorf("expected error for too many get args")
	}
	if err := cli.HandleGet([]string{"bad"}); err == nil || !strings.Contains(err.Error(), "expected 64-character") {
		t.Errorf("expected 64-char hex error for 'get bad', got: %v", err)
	}
	if err := cli.HandleGet([]string{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}); err == nil {
		t.Errorf("expected error for non-existent key")
	}

	// Forget key
	out.Reset()
	err = cli.HandleForget([]string{dataKey.String()})
	if err != nil {
		t.Fatalf("forget failed: %v", err)
	}
	if !strings.Contains(out.String(), "successfully forgotten") {
		t.Errorf("expected forgotten message, got: %s", out.String())
	}

	// Verify key is gone from DataStore
	if kad.DataStore.Has(*dataKey) {
		t.Errorf("expected key to be removed from DataStore")
	}

	// Forget again -> not found
	out.Reset()
	err = cli.HandleForget([]string{dataKey.String()})
	if err != nil {
		t.Fatalf("forget should not return error for missing key: %v", err)
	}
	if !strings.Contains(out.String(), "not found") {
		t.Errorf("expected not found message, got: %s", out.String())
	}

	// Forget invalid args and invalid keys
	if err := cli.HandleForget([]string{}); err == nil {
		t.Errorf("expected error for missing forget args")
	}
	if err := cli.HandleForget([]string{"bad"}); err == nil || !strings.Contains(err.Error(), "expected 64-character") {
		t.Errorf("expected 64-char hex error for 'forget bad', got: %v", err)
	}
}

func TestCLI_Show_Routing_And_DataStore(t *testing.T) {
	cli, kad, _, _, out := setupTestCLI(t)

	// Show RT empty
	out.Reset()
	if err := cli.HandleShow([]string{"rt"}); err != nil {
		t.Fatalf("show rt failed: %v", err)
	}
	if !strings.Contains(out.String(), "empty") {
		t.Errorf("expected empty routing table message, got: %s", out.String())
	}

	// Add contact and show routing
	targetID := kademlia.NewKademliaID("3000000000000000000000000000000000000000000000000000000000000003")
	kad.RoutingTable.AddContact(kademlia.NewContact(targetID, "sim:node3"))
	out.Reset()
	if err := cli.HandleShow([]string{"routing"}); err != nil {
		t.Fatalf("show routing failed: %v", err)
	}
	if !strings.Contains(out.String(), "Routing table for node") {
		t.Errorf("expected table header, got: %s", out.String())
	}

	// Show DS empty
	out.Reset()
	if err := cli.HandleShow([]string{"ds"}); err != nil {
		t.Fatalf("show ds failed: %v", err)
	}
	if !strings.Contains(out.String(), "empty") {
		t.Errorf("expected empty datastore message, got: %s", out.String())
	}

	// Put raw blob, VersionRecord, and LatestPointer, then inspect show ds
	domain := "example.com"
	pkg := "test-ds-pkg"
	dkp, _ := registry.GenerateDomainKeyPair(domain)

	blobData := []byte("binary payload")
	blobHash := registry.ComputeBlobHash(blobData)
	_, _ = kad.Store(blobData)

	vr, _ := registry.NewInitialVersionRecord(domain, pkg, "1.0.0", blobHash)
	_ = vr.Sign(dkp.PrivateKey)
	vrBytes, _ := vr.MarshalJSON()
	_, _ = kad.Store(vrBytes)

	lp, _ := vr.NewLatestPointer()
	_ = lp.Sign(dkp.PrivateKey)
	_ = kad.StoreLatestPointerForce(lp)

	out.Reset()
	if err := cli.HandleShow([]string{"ds"}); err != nil {
		t.Fatalf("show ds with items failed: %v", err)
	}
	dsOutput := out.String()
	if !strings.Contains(dsOutput, "[VersionRecord]") {
		t.Errorf("expected [VersionRecord] in show ds, got: %s", dsOutput)
	}
	if !strings.Contains(dsOutput, "[LatestPointer]") {
		t.Errorf("expected [LatestPointer] in show ds, got: %s", dsOutput)
	}
	if !strings.Contains(dsOutput, "[Blob]") {
		t.Errorf("expected [Blob] in show ds, got: %s", dsOutput)
	}
	if !strings.Contains(dsOutput, "Summary:") {
		t.Errorf("expected Summary in show ds, got: %s", dsOutput)
	}

	// Show unknown option
	if err := cli.HandleShow([]string{"unknown"}); err == nil {
		t.Errorf("expected error for unknown show option")
	}
	if err := cli.HandleShow([]string{}); err == nil {
		t.Errorf("expected error for empty show args")
	}
}

func TestCLI_Show_DNS_And_Keygen(t *testing.T) {
	cli, _, _, resolver, out := setupTestCLI(t)

	// Show DNS missing domain
	if err := cli.HandleShow([]string{"dns"}); err == nil {
		t.Errorf("expected error for missing domain in show dns")
	}

	// Show DNS not found
	out.Reset()
	if err := cli.HandleShow([]string{"dns", "unknown.org"}); err != nil {
		t.Fatalf("show dns not found should not fail with error: %v", err)
	}
	if !strings.Contains(out.String(), "NOT FOUND") {
		t.Errorf("expected NOT FOUND in output, got: %s", out.String())
	}

	// Keygen
	out.Reset()
	if err := cli.HandleKeygen([]string{"myregistry.org"}); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	if !strings.Contains(out.String(), "Generated new key pair") {
		t.Errorf("expected keygen success output, got: %s", out.String())
	}

	// Show DNS for newly generated domain
	out.Reset()
	if err := cli.HandleShow([]string{"dns", "myregistry.org"}); err != nil {
		t.Fatalf("show dns failed: %v", err)
	}
	if !strings.Contains(out.String(), "VERIFIED") {
		t.Errorf("expected VERIFIED status for generated key, got: %s", out.String())
	}

	// Keygen error cases
	if err := cli.HandleKeygen([]string{}); err == nil {
		t.Errorf("expected error for missing domain in keygen")
	}
	if err := cli.HandleKeygen([]string{"invalid..domain"}); err == nil {
		t.Errorf("expected error for malformed domain in keygen")
	}

	_ = resolver
}

func TestCLI_Publish_And_Install_E2E(t *testing.T) {
	cli, kad, km, resolver, out := setupTestCLI(t)
	tempDir := t.TempDir()

	domain := "acme.org"
	pkg := "cool-tool"

	// Generate domain key pair
	dkp, err := km.Generate(domain)
	if err != nil {
		t.Fatalf("km.Generate failed: %v", err)
	}
	_ = resolver.SetKey(domain, dkp.PublicKey)

	// Create package binary file v1.0.0
	pkgFile1 := filepath.Join(tempDir, "cool-tool-1.0.0.bin")
	if err := os.WriteFile(pkgFile1, []byte("binary payload v1.0.0"), 0644); err != nil {
		t.Fatalf("failed to write pkgFile1: %v", err)
	}

	// Publish initial release v1.0.0
	out.Reset()
	publishCmd := []string{domain + ":" + pkg + ":1.0.0", pkgFile1}
	if err := cli.HandlePublish(publishCmd); err != nil {
		t.Fatalf("HandlePublish v1.0.0 failed: %v", err)
	}
	publishOut := out.String()
	if !strings.Contains(publishOut, "Successfully published package") {
		t.Errorf("expected publish success message, got: %s", publishOut)
	}
	if !strings.Contains(publishOut, "Blob Hash:") || !strings.Contains(publishOut, "Version Record:") {
		t.Errorf("missing hashes in publish output: %s", publishOut)
	}

	// Install latest (should resolve to 1.0.0)
	destInstallLatest := filepath.Join(tempDir, "installed-latest.bin")
	out.Reset()
	installCmd := []string{domain + ":" + pkg + ":latest", destInstallLatest}
	if err := cli.HandleInstall(installCmd); err != nil {
		t.Fatalf("HandleInstall latest failed: %v", err)
	}
	installedBytes, err := os.ReadFile(destInstallLatest)
	if err != nil || string(installedBytes) != "binary payload v1.0.0" {
		t.Errorf("installed binary mismatch: %q, err: %v", string(installedBytes), err)
	}

	// Publish v2.0.0 incremental release
	pkgFile2 := filepath.Join(tempDir, "cool-tool-2.0.0.bin")
	if err := os.WriteFile(pkgFile2, []byte("binary payload v2.0.0 updated"), 0644); err != nil {
		t.Fatalf("failed to write pkgFile2: %v", err)
	}
	out.Reset()
	if err := cli.HandlePublish([]string{domain + ":" + pkg + ":2.0.0", pkgFile2}); err != nil {
		t.Fatalf("HandlePublish v2.0.0 failed: %v", err)
	}

	// Install specific older version v1.0.0 (walks chain from v2.0.0 head back to v1.0.0)
	destInstallOld := filepath.Join(tempDir, "installed-v1.bin")
	out.Reset()
	if err := cli.HandleInstall([]string{domain + ":" + pkg + ":1.0.0", destInstallOld}); err != nil {
		t.Fatalf("HandleInstall specific 1.0.0 failed: %v", err)
	}
	installedOld, err := os.ReadFile(destInstallOld)
	if err != nil || string(installedOld) != "binary payload v1.0.0" {
		t.Errorf("downloaded v1.0.0 binary mismatch: %q, err: %v", string(installedOld), err)
	}

	// Install default filename (no dest filename specified)
	out.Reset()
	// Change working directory or let it write in current dir, then clean up
	defaultFilename := pkg + "-2.0.0.bin"
	defer os.Remove(defaultFilename)
	if err := cli.HandleInstall([]string{domain + ":" + pkg + ":2.0.0"}); err != nil {
		t.Fatalf("HandleInstall with default filename failed: %v", err)
	}
	if _, err := os.Stat(defaultFilename); err != nil {
		t.Errorf("expected default filename %q to exist", defaultFilename)
	}

	// Install non-existent version 0.5.0
	if err := cli.HandleInstall([]string{domain + ":" + pkg + ":0.5.0"}); err == nil {
		t.Errorf("expected error installing non-existent version 0.5.0")
	}

	// Show DOMAIN:PACKAGE version chain
	out.Reset()
	if err := cli.HandleShow([]string{domain + ":" + pkg}); err != nil {
		t.Fatalf("HandleShow package failed: %v", err)
	}
	showChain := out.String()
	if !strings.Contains(showChain, "Version History Chain (2 versions") {
		t.Errorf("expected 2 versions in chain output, got: %s", showChain)
	}
	if !strings.Contains(showChain, "v2.0.0 (LATEST)") || !strings.Contains(showChain, "v1.0.0 (INITIAL RELEASE)") {
		t.Errorf("expected both v2.0.0 and v1.0.0 tags, got: %s", showChain)
	}

	_ = kad
}

func TestCLI_Publish_PreflightAndForce(t *testing.T) {
	cli, _, km, resolver, out := setupTestCLI(t)
	tempDir := t.TempDir()

	domain := "security.org"
	pkg := "guarded-pkg"

	sampleFile := filepath.Join(tempDir, "app.bin")
	_ = os.WriteFile(sampleFile, []byte("app code"), 0644)

	// Missing private key without force -> error
	err := cli.HandlePublish([]string{domain + ":throwaway-pkg:1.0.0", sampleFile})
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("expected private key error when key not found, got: %v", err)
	}

	// Publish with --force even when key is missing (creates ephemeral key)
	out.Reset()
	err = cli.HandlePublish([]string{"--force", domain + ":throwaway-pkg:1.0.0", sampleFile})
	if err != nil {
		t.Fatalf("forced publish with missing key should succeed locally: %v", err)
	}
	if !strings.Contains(out.String(), "--force") {
		t.Errorf("expected --force note in output, got: %s", out.String())
	}

	// DNS mismatch pre-flight check
	dkp, _ := km.Generate(domain)
	// Register DIFFERENT key in DNS
	dkpOther, _ := registry.GenerateDomainKeyPair(domain)
	_ = resolver.SetKey(domain, dkpOther.PublicKey)

	err = cli.HandlePublish([]string{domain + ":" + pkg + ":2.0.0", sampleFile})
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected DNS mismatch error, got: %v", err)
	}

	// Fix DNS key
	_ = resolver.SetKey(domain, dkp.PublicKey)

	// Version Rollback preflight check
	// First publish 2.0.0 legitimately
	err = cli.HandlePublish([]string{domain + ":" + pkg + ":2.0.0", sampleFile})
	if err != nil {
		t.Fatalf("publish 2.0.0 failed: %v", err)
	}

	// Now try to publish rollback (1.5.0) without force -> rejected!
	err = cli.HandlePublish([]string{domain + ":" + pkg + ":1.5.0", sampleFile})
	if err == nil || !strings.Contains(err.Error(), "rollback rejected") {
		t.Errorf("expected rollback rejected error, got: %v", err)
	}

	// Publish rollback WITH --force -> accepted locally for network demonstration
	out.Reset()
	err = cli.HandlePublish([]string{"--force", domain + ":" + pkg + ":1.5.0", sampleFile})
	if err != nil {
		t.Fatalf("forced rollback failed: %v", err)
	}

	// Explicit --prev flag
	chainPkg := "chain-pkg"
	_ = cli.HandlePublish([]string{domain + ":" + chainPkg + ":1.0.0", sampleFile})
	_ = cli.HandlePublish([]string{domain + ":" + chainPkg + ":2.0.0", sampleFile})

	// Publish 3.0.0 linking explicitly to 2.0.0
	out.Reset()
	err = cli.HandlePublish([]string{"--prev=2.0.0", domain + ":" + chainPkg + ":3.0.0", sampleFile})
	if err != nil {
		t.Fatalf("publish with --prev=2.0.0 failed: %v", err)
	}

	// Publish with older predecessor without force -> fork rejected!
	err = cli.HandlePublish([]string{"--prev=1.0.0", domain + ":" + chainPkg + ":4.0.0", sampleFile})
	if err == nil || !strings.Contains(err.Error(), "fork rejected") {
		t.Errorf("expected fork rejected error for --prev=1.0.0 without force, got: %v", err)
	}

	// Publish fork off 1.0.0 WITH --force -> allowed locally to test network rejection
	err = cli.HandlePublish([]string{"--force", "--prev=1.0.0", domain + ":" + chainPkg + ":4.0.0", sampleFile})
	if err != nil {
		t.Fatalf("forced fork off 1.0.0 should succeed locally: %v", err)
	}

	// Publish with arbitrary hex hash WITH --force -> allowed locally to test network rejection
	forcedHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err = cli.HandlePublish([]string{"--force", "--prev=" + forcedHash, domain + ":" + chainPkg + ":5.0.0", sampleFile})
	if err != nil {
		t.Fatalf("forced publish with explicit record hash should succeed locally: %v", err)
	}

	// Publish with non-existent --prev without force -> error
	err = cli.HandlePublish([]string{"--prev=9.9.9", domain + ":" + chainPkg + ":6.0.0", sampleFile})
	if err == nil || !strings.Contains(err.Error(), "not found in chain") {
		t.Errorf("expected previous version not found error, got: %v", err)
	}

	// Malformed arguments and flags
	if err := cli.HandlePublish([]string{}); err == nil {
		t.Errorf("expected error for empty publish args")
	}
	if err := cli.HandlePublish([]string{"--badflag", domain + ":" + pkg + ":5.0.0", sampleFile}); err == nil {
		t.Errorf("expected error for bad flag")
	}
	if err := cli.HandlePublish([]string{"badformat", sampleFile}); err == nil {
		t.Errorf("expected error for bad target format")
	}
	if err := cli.HandlePublish([]string{domain + ":" + pkg + ":5.0.0", "/nonexistent/file.bin"}); err == nil {
		t.Errorf("expected error for missing file")
	}

	// Publish with inline quoted string payload
	inlineCmd := `publish ` + domain + `:inline-pkg:1.0.0 "function hello() { return 'v1.0.0'; }"`
	shouldExit, err := cli.Execute(inlineCmd)
	if err != nil || shouldExit {
		t.Fatalf("expected successful publish of inline quoted string payload, got err: %v", err)
	}
}

func TestCLI_Interactive_RunLoop(t *testing.T) {
	kadMe := kademlia.NewContact(kademlia.NewKademliaID("7000000000000000000000000000000000000000000000000000000000000007"), "sim:node7")
	kad := kademlia.NewKademlia(kadMe, nil, kademlia.NewRoutingTable(kadMe), kademlia.NewDataStore(), 3)
	out := &bytes.Buffer{}
	in := strings.NewReader("help\nshow rt\nexit\n")

	cli := NewCLI(kad, nil, nil, in, out)
	cli.Run()

	runOutput := out.String()
	if !strings.Contains(runOutput, "Available Commands:") {
		t.Errorf("expected help output during interactive run, got: %s", runOutput)
	}
	if !strings.Contains(runOutput, "Thank you for using this Kademlia interactive CLI!") {
		t.Errorf("expected exit message during interactive run, got: %s", runOutput)
	}
}

func TestNodeDNSResolver(t *testing.T) {
	resolver := NewNodeDNSResolver()

	// Empty domain
	if _, err := resolver.LookupOwnerKey(""); err == nil {
		t.Errorf("expected error for empty domain")
	}

	// Not found
	if _, err := resolver.LookupOwnerKey("nonexistent.local"); err == nil {
		t.Errorf("expected error for non-existent domain")
	}

	// SetKey and Lookup
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := resolver.SetKey("test.org", pub); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}
	foundPub, err := resolver.LookupOwnerKey("test.org")
	if err != nil || !bytes.Equal(foundPub, pub) {
		t.Errorf("LookupOwnerKey returned mismatch: %v, err: %v", foundPub, err)
	}

	// SetKeyHex
	hexPub := registry.EncodePublicKeyHex(pub)
	if err := resolver.SetKeyHex("hex.org", hexPub); err != nil {
		t.Fatalf("SetKeyHex failed: %v", err)
	}
	domains := resolver.ListDomains()
	if len(domains) < 2 {
		t.Errorf("expected at least 2 domains, got %v", domains)
	}
}

func TestMainHelperFunctions(t *testing.T) {
	// truncateID
	if truncateID("1234") != "1234" {
		t.Errorf("expected short ID unchanged")
	}
	longID := "1234567890abcdef"
	if truncateID(longID) != "1234...cdef" {
		t.Errorf("expected 1234...cdef, got %s", truncateID(longID))
	}

	// getEnv
	if getEnv("NONEXISTENT_ENV_VAR_TEST", "fallback") != "fallback" {
		t.Errorf("expected fallback value")
	}
	os.Setenv("TEST_ENV_VAR", "actual")
	defer os.Unsetenv("TEST_ENV_VAR")
	if getEnv("TEST_ENV_VAR", "fallback") != "actual" {
		t.Errorf("expected actual env value")
	}

	// trimPortFromAddress
	ip, err := trimPortFromAddress("192.168.1.1:8000")
	if err != nil || ip != "192.168.1.1" {
		t.Errorf("unexpected ip trim: %s, %v", ip, err)
	}
	_, err = trimPortFromAddress("invalid_address")
	if err == nil {
		t.Errorf("expected error for invalid address")
	}

	// FindContactByAddress
	contacts := []kademlia.Contact{
		kademlia.NewContact(kademlia.NewKademliaID("1111111111111111111111111111111111111111111111111111111111111111"), "10.0.0.1:8000"),
		kademlia.NewContact(kademlia.NewKademliaID("2222222222222222222222222222222222222222222222222222222222222222"), "10.0.0.2:8000"),
	}
	c, err := FindContactByAddress(contacts, "10.0.0.1:8000")
	if err != nil || c.Address != "10.0.0.1:8000" {
		t.Errorf("FindContactByAddress failed: %v, err: %v", c, err)
	}
	if _, err := FindContactByAddress(contacts, "10.0.0.99:8000"); err == nil {
		t.Errorf("expected error for missing address")
	}

	// FindContactByID (prefix)
	c, err = FindContactByID(contacts, "1111")
	if err != nil || !c.ID.Equals(contacts[0].ID) {
		t.Errorf("FindContactByID failed: %v, err: %v", c, err)
	}
	if _, err := FindContactByID(contacts, "9999"); err == nil {
		t.Errorf("expected error for missing prefix")
	}

	// Ambiguous prefix
	dupContacts := []kademlia.Contact{
		kademlia.NewContact(kademlia.NewKademliaID("aaaa111111111111111111111111111111111111111111111111111111111111"), "10.0.0.1:8000"),
		kademlia.NewContact(kademlia.NewKademliaID("aaaa222222222222222222222222222222222222222222222222222222222222"), "10.0.0.2:8000"),
	}
	if _, err := FindContactByID(dupContacts, "aaaa"); err == nil {
		t.Errorf("expected ambiguous prefix error")
	}
}

func TestCreateNode_And_LocalIP_And_RunCLIWithIO(t *testing.T) {
	tempDir := t.TempDir()

	// getLocalIP
	ip, err := getLocalIP()
	if err != nil {
		t.Logf("getLocalIP returned error (acceptable in some container environments without external iface): %v", err)
	} else if ip == "" {
		t.Errorf("expected non-empty ip string")
	}

	// createNode with ephemeral port 0 on loopback
	kad, net, km, resolver, err := createNode("127.0.0.1", "127.0.0.1", 0, filepath.Join(tempDir, "nodekeys"))
	if err != nil {
		t.Fatalf("createNode failed: %v", err)
	}
	defer net.Close()

	if kad == nil || km == nil || resolver == nil {
		t.Fatalf("expected non-nil components from createNode")
	}

	// runCLIWithIO
	out := &bytes.Buffer{}
	runCLIWithIO(kad, km, resolver, strings.NewReader("help\nexit\n"), out)
	if !strings.Contains(out.String(), "Available Commands:") {
		t.Errorf("expected help output from runCLIWithIO, got: %s", out.String())
	}

	// isCanonicalHexHash
	validHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !isCanonicalHexHash(validHex) {
		t.Errorf("expected true for valid canonical hex")
	}
	if isCanonicalHexHash("short") {
		t.Errorf("expected false for short string")
	}
	if isCanonicalHexHash("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Errorf("expected false for uppercase hex")
	}
	if isCanonicalHexHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg") {
		t.Errorf("expected false for non-hex character")
	}
}

func TestCLI_Execute_DispatchCoverage(t *testing.T) {
	cli, _, _, _, _ := setupTestCLI(t)
	tempDir := t.TempDir()

	testFile := filepath.Join(tempDir, "sample.bin")
	_ = os.WriteFile(testFile, []byte("data"), 0644)

	// Execute PING
	_, _ = cli.Execute("ping 1234")

	// Execute PUT
	_, _ = cli.Execute("put " + testFile)

	// Execute GET
	_, _ = cli.Execute("get 1234567890123456789012345678901234567890123456789012345678901234")

	// Execute FORGET
	_, _ = cli.Execute("forget 1234567890123456789012345678901234567890123456789012345678901234")

	// Execute SHOW
	_, _ = cli.Execute("show rt")

	// Execute PUBLISH
	_, _ = cli.Execute("publish --force example.com:mypkg:1.0.0 " + testFile)

	// Execute INSTALL
	_, _ = cli.Execute("install example.com:mypkg:latest")

	// Execute KEYGEN
	_, _ = cli.Execute("keygen example.com")
}

func TestCLI_NilGuards_And_Defaults(t *testing.T) {
	// NewCLI with nil In and Out
	cliNil := NewCLI(nil, nil, nil, nil, nil)
	if cliNil.In == nil || cliNil.Out == nil {
		t.Errorf("expected default In and Out when nil provided")
	}

	// Guard clauses when components are nil
	if err := cliNil.HandlePing([]string{"1234"}); err == nil {
		t.Errorf("expected error for nil kad in HandlePing")
	}
	if err := cliNil.HandleForget([]string{"1234"}); err == nil {
		t.Errorf("expected error for nil kad in HandleForget")
	}
	if err := cliNil.showRoutingTable(); err == nil {
		t.Errorf("expected error for nil kad in showRoutingTable")
	}
	if err := cliNil.showDataStore(); err == nil {
		t.Errorf("expected error for nil kad in showDataStore")
	}
	if err := cliNil.showDNS("example.com"); err == nil {
		t.Errorf("expected error for nil resolver in showDNS")
	}
	if err := cliNil.HandleKeygen([]string{"example.com"}); err == nil {
		t.Errorf("expected error for nil km in HandleKeygen")
	}

	// NodeDNSResolver with nil mock
	emptyResolver := &NodeDNSResolver{}
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = emptyResolver.SetKey("test.org", pub)
	_ = emptyResolver.SetKeyHex("test2.org", registry.EncodePublicKeyHex(pub))
	domains := emptyResolver.ListDomains()
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %v", domains)
	}

	// Test runCLI via redirected stdin
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err == nil {
		os.Stdin = r
		w.WriteString("exit\n")
		w.Close()
		runCLI(nil, nil, nil)
		os.Stdin = oldStdin
		r.Close()
	}
}

func TestCLI_AdditionalValidationCoverage(t *testing.T) {
	cli, _, km, resolver, _ := setupTestCLI(t)
	tempDir := t.TempDir()

	validFile := filepath.Join(tempDir, "valid.bin")
	_ = os.WriteFile(validFile, []byte("content"), 0644)
	emptyFile := filepath.Join(tempDir, "empty.bin")
	_ = os.WriteFile(emptyFile, []byte{}, 0644)

	// Publish empty file
	if err := cli.HandlePublish([]string{"example.com:pkg:1.0.0", emptyFile}); err == nil {
		t.Errorf("expected error for empty file")
	}

	// Publish missing value for flag --prev
	if err := cli.HandlePublish([]string{"--prev", "example.com:pkg:1.0.0", validFile}); err == nil {
		t.Errorf("expected error for missing --prev value")
	}

	// Publish invalid domain
	if err := cli.HandlePublish([]string{"invalid..domain:pkg:1.0.0", validFile}); err == nil {
		t.Errorf("expected error for invalid domain")
	}

	// Publish invalid pkg
	if err := cli.HandlePublish([]string{"example.com:bad/pkg:1.0.0", validFile}); err == nil {
		t.Errorf("expected error for invalid pkg name")
	}

	// Publish invalid version
	if err := cli.HandlePublish([]string{"example.com:pkg:badversion", validFile}); err == nil {
		t.Errorf("expected error for invalid semantic version")
	}

	// Initial release with --prev=none
	dkp, _ := km.Generate("none-prev.org")
	_ = resolver.SetKey("none-prev.org", dkp.PublicKey)
	if err := cli.HandlePublish([]string{"--prev=none", "none-prev.org:pkg:1.0.0", validFile}); err != nil {
		t.Errorf("expected --prev=none to succeed for initial release: %v", err)
	}

	// Initial release with --prev=1.0.0 without force
	dkp2, _ := km.Generate("initial-err.org")
	_ = resolver.SetKey("initial-err.org", dkp2.PublicKey)
	if err := cli.HandlePublish([]string{"--prev=1.0.0", "initial-err.org:pkg:1.0.0", validFile}); err == nil {
		t.Errorf("expected error for initial release linking to previous version")
	}

	// show package format errors
	if err := cli.showPackage("bad:pkg:extra"); err == nil {
		t.Errorf("expected error for show with extra segments")
	}
	if err := cli.showPackage("bad..domain:pkg"); err == nil {
		t.Errorf("expected error for show with invalid domain")
	}
	if err := cli.showPackage("example.com:bad/pkg"); err == nil {
		t.Errorf("expected error for show with invalid package name")
	}

	// install argument errors
	if err := cli.HandleInstall([]string{"bad_target"}); err == nil {
		t.Errorf("expected error for invalid install target format")
	}
	if err := cli.HandleInstall([]string{"example.com:pkg:invalid_ver"}); err == nil {
		t.Errorf("expected error for invalid requested version")
	}

	// Publish & Install with space-separated syntax
	spaceDomain := "spacesyntax.org"
	dkpSpace, _ := km.Generate(spaceDomain)
	_ = resolver.SetKey(spaceDomain, dkpSpace.PublicKey)
	spaceFile := filepath.Join(tempDir, "spacesyntax.bin")
	_ = os.WriteFile(spaceFile, []byte("space syntax content"), 0644)

	if err := cli.HandlePublish([]string{spaceDomain, "my-space-pkg", "1.0.0", spaceFile}); err != nil {
		t.Fatalf("publish with space-separated syntax failed: %v", err)
	}

	destSpace := filepath.Join(tempDir, "sub", "dir", "installed_space.bin")
	if err := cli.HandleInstall([]string{spaceDomain, "my-space-pkg", "1.0.0", destSpace}); err != nil {
		t.Fatalf("install with space-separated syntax and nested dir failed: %v", err)
	}
	dataRead, err := os.ReadFile(destSpace)
	if err != nil || string(dataRead) != "space syntax content" {
		t.Errorf("content mismatch for space syntax install: %q, err: %v", string(dataRead), err)
	}

	// Show package with space-separated syntax and show package prefix
	if err := cli.HandleShow([]string{spaceDomain, "my-space-pkg"}); err != nil {
		t.Errorf("show with space-separated syntax failed: %v", err)
	}
	if err := cli.HandleShow([]string{"package", spaceDomain + ":my-space-pkg"}); err != nil {
		t.Errorf("show package <domain>:<pkg> failed: %v", err)
	}
	if err := cli.HandleShow([]string{"pkg", spaceDomain, "my-space-pkg"}); err != nil {
		t.Errorf("show pkg <domain> <pkg> failed: %v", err)
	}

	// Forced publish on initial release with explicit 64-char hex hash
	forcedHex := "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
	forcedDomain := "forcedhex.org"
	dkpForced, _ := km.Generate(forcedDomain)
	_ = resolver.SetKey(forcedDomain, dkpForced.PublicKey)

	if err := cli.HandlePublish([]string{"--force", "--prev=" + forcedHex, forcedDomain + ":hexpkg:1.0.0", validFile}); err != nil {
		t.Fatalf("forced publish with explicit hex hash on initial release failed: %v", err)
	}

	// Verify the published VersionRecord links to forcedHex
	lp, _, err := cli.Kad.LookupLatestPointer(forcedDomain, "hexpkg")
	if err != nil || lp == nil {
		t.Fatalf("lookup latest pointer failed: %v", err)
	}
	vrData, _, err := cli.Kad.LookupData(lp.VersionRecordHash)
	if err != nil {
		t.Fatalf("lookup version record failed: %v", err)
	}
	vr, err := registry.ParseVersionRecord(vrData)
	if err != nil {
		t.Fatalf("parse version record failed: %v", err)
	}
	if vr.PreviousVersionRecord != forcedHex {
		t.Errorf("expected previous version record to be %s, got: %s", forcedHex, vr.PreviousVersionRecord)
	}

	// Existing package linking to ZeroHash without force -> rejected!
	if err := cli.HandlePublish([]string{"--prev=0", spaceDomain + ":my-space-pkg:2.0.0", validFile}); err == nil {
		t.Errorf("expected error attempting to link existing package to zero previous record without force")
	}

	// Existing package linking to ZeroHash WITH force -> allowed!
	if err := cli.HandlePublish([]string{"--force", "--prev=0", spaceDomain + ":my-space-pkg:2.0.0", validFile}); err != nil {
		t.Fatalf("forced publish with zero prev on existing package should succeed: %v", err)
	}

	// Existing package linking to explicit latest record hash without force -> allowed!
	lpCurrent, _, _ := cli.Kad.LookupLatestPointer(spaceDomain, "my-space-pkg")
	if err := cli.HandlePublish([]string{"--prev=" + lpCurrent.VersionRecordHash, spaceDomain + ":my-space-pkg:3.0.0", validFile}); err != nil {
		t.Fatalf("publish with explicit latest record hash should succeed: %v", err)
	}

	// Show DataStore with multi-byte UTF-8 data
	chineseData := []byte("你好世界，这是一个分布式系统包管理器测试！")
	_, _ = cli.Kad.Store(chineseData)
	outBuf := &bytes.Buffer{}
	cli.Out = outBuf
	if err := cli.showDataStore(); err != nil {
		t.Errorf("showDataStore with multi-byte data failed: %v", err)
	}
	if !strings.Contains(outBuf.String(), "你好世界") {
		t.Errorf("expected multi-byte data in show ds, got: %s", outBuf.String())
	}
}

func TestCLI_HandleSet(t *testing.T) {
	resolver := NewNodeDNSResolver()
	cli := &CLI{
		Resolver: resolver,
		Out:      io.Discard,
	}

	// Invalid args
	if err := cli.HandleSet([]string{}); err == nil {
		t.Error("expected error for empty args")
	}
	if err := cli.HandleSet([]string{"not-dns", "domain.com", "1234"}); err == nil {
		t.Error("expected error for non-dns set command")
	}

	// Valid set dns
	domain := "custom-domain.org"
	dkp, err := registry.GenerateDomainKeyPair(domain)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	hexKey := registry.EncodePublicKeyHex(dkp.PublicKey)

	if err := cli.HandleSet([]string{"dns", domain, hexKey}); err != nil {
		t.Fatalf("expected successful set dns, got: %v", err)
	}

	// Verify lookup
	lookedUp, err := resolver.LookupOwnerKey(domain)
	if err != nil {
		t.Fatalf("failed to lookup key: %v", err)
	}
	if !bytes.Equal(lookedUp, dkp.PublicKey) {
		t.Errorf("looked up key mismatch")
	}

	// Test Execute("set dns ...")
	exit, err := cli.Execute("set dns " + domain + " " + hexKey)
	if err != nil || exit {
		t.Errorf("Execute set dns failed: %v", err)
	}

	// Test KeyManager integration in NodeDNSResolver
	tempDir := t.TempDir()
	km, err := registry.NewKeyManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}
	dkpKM, _ := km.Generate("km-domain.org")

	emptyResolver := NewNodeDNSResolver()
	emptyResolver.SetKeyManager(km)
	lookedUpKM, err := emptyResolver.LookupOwnerKey("km-domain.org")
	if err != nil {
		t.Fatalf("expected KeyManager key lookup to succeed: %v", err)
	}
	if !bytes.Equal(lookedUpKM, dkpKM.PublicKey) {
		t.Errorf("looked up KM key mismatch")
	}
}
