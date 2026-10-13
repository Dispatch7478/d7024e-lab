# Decentralized Package Registry on Kademlia DHT
> **Course**: D7024E Distributed Systems — Luleå University of Technology (LTU)  
> **Repository**: [https://github.com/Dispatch7478/d7024e-lab](https://github.com/Dispatch7478/d7024e-lab)

---

## Project Highlights & Quality Metrics

- **Overall Statement Coverage**: **`87.1%`**
  - `d7024e/registry`: **`91.5%`**
  - `d7024e/kademlia`: **`88.8%`**
  - `d7024e/cmd/node`: **`85.5%`**
- **Thread Safety**: **100% Data-Race Free** (`go test -race ./...` reports 0 data races)
- **Scalability**: Tested up to **1,000+ nodes** concurrently on the in-memory simulated message hub.
- **Containerization**: Fully containerized cluster scalable to **50+ independent node containers** via Docker Compose on a dedicated bridge network (`172.20.0.0/16`).

---

## System Architecture

The project is structured in two architectural layers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Layer 2: Decentralized Package Registry              │
│  - DNS Identity Oracle (RFC 1035 TXT records / Ed25519 Signatures)     │
│  - Immutable Content-Addressed Version Records (K = SHA-256(VR))       │
│  - Mutable Latest Pointers (K = SHA-256(domain:pkg:latest))            │
│  - 4-Stage Security Validation Pipeline (Auth, Rollback, Fork, Catchup)│
│  - Optimistic Concurrency Control (OCC) Lock-Free Traversal Engine     │
└───────────────────────────────────▲────────────────────────────────────┘
                                    │
┌───────────────────────────────────┴────────────────────────────────────┐
│                    Layer 1: Kademlia                                   │
│  - 256-bit Identifier Keyspace with XOR Distance Metric                │
│  - Routing Table with 256 k-buckets (k=10) & Least-Recently-Seen Evict │
│  - Iterative Lookups with α=3 Parallel Probing (Shortlist Engine)      │
│  - Background Churn Replication Worker (DefaultReplicationInterval)    │
│  - Transport Abstraction (UDPNetwork for Docker, SimulatedHub for Test)│
└────────────────────────────────────────────────────────────────────────┘
```

---

## Testing & Code Coverage

### Run All Unit and Integration Tests
```bash
make test
# Or directly with Go:
go test -v -count=1 ./...
```

### Run Tests with Race Detector
To verify complete thread safety across all concurrent operations:
```bash
go test -race ./...
```

### Inspect Test Coverage
Generate a statement coverage breakdown across all project modules:
```bash
go test -cover ./...
```
To generate and view an HTML coverage report:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

---

## Docker Deployment (50 Replicas)

The system includes a fully configured Docker Compose setup capable of spinning up a 50-node peer-to-peer network on your local machine.

### Prerequisites
- Docker Engine $\ge 20.10$
- Docker Compose v2

### 1. Build and Start 50 Nodes
```bash
# Builds the static Go binary and Docker image, then boots 50 node containers + 1 bootstrap node:
make run
```
Or start with a custom replica scale:
```bash
# Start exactly 50 worker nodes:
make up NODES=50

# For small tests:
make reset NODES=5
```

### 2. Inspect Running Containers
```bash
docker ps
```
The topology consists of:
- `kademlia-bootstrap`: Fixed IP `172.20.0.2:8000`
- `d7024e-lab-kademliaNodes-1` through `50`: Dynamically assigned IPs `172.20.0.3` to `172.20.0.52`

### 3. Stop and Clean Cluster
```bash
# Stop containers:
make down

# Complete wipe (stops containers, cleans generated keys and temp downloads):
make clean
```

---

## Attaching & Interacting with Nodes

Each container runs the interactive `kadlab` CLI attached to `stdin`/`stdout`.

### Attach to a Specific Worker Node
```bash
# Attach to Node 6:
make attach NODE=6

# Attach to Node 7:
make attach NODE=7
```

### Attach to the Bootstrap Node
```bash
make attach-bootstrap
```

### View Live Cluster Logs
```bash
make logs
```

### Open a Bash/Sh Shell Inside a Node Container
```bash
make shell NODE=1
```

---

## CLI Command Reference

Once attached to a node, the interactive prompt `>` supports the following commands:

### Part 1: Kademlia Core DHT Commands

| Command | Syntax | Description | Example |
|---|---|---|---|
| `ping` | `ping <IP:PORT \| ID>` | Dispatches a `PING` RPC and measures round-trip latency. | `ping 172.20.0.2:8000` |
| `put` | `put <FILENAME>` | Uploads file contents into the DHT under its SHA-256 hash. | `put /data/test.txt` |
| `get` | `get <HASH> [DEST_FILE]` | Retrieves a value by its 256-bit hex hash from the network. | `get 2e921f... /data/out.txt` |
| `show rt` | `show rt` (or `show routing`) | Prints all non-empty k-buckets in the node's routing table. | `show rt` |
| `show ds` | `show ds` | Lists all stored keys in the local DataStore with record types. | `show ds` |
| `exit` | `exit` (or `quit`) | Terminates the CLI session and shuts down the node. | `exit` |

### Part 2: Decentralized Package Registry Commands

| Command | Syntax | Description | Example |
|---|---|---|---|
| `keygen` | `keygen <DOMAIN>` | Generates an Ed25519 keypair saved to `keys/<domain>.json` and registers with DNS cache. | `keygen mydomain.com` |
| `set dns` | `set dns <DOMAIN> <PUBKEY_HEX>` | Manually maps a domain to an Ed25519 public key in the local resolver. | `set dns mydomain.com e91740...` |
| `show dns` | `show dns <DOMAIN>` | Inspects what the node resolves as the authorized public key for a domain. | `show dns mydomain.com` |
| `publish` | `publish [--force] [--prev=VER] <DOM:PKG:VER> <FILE>` | Publishes a new package release into the registry. | `publish mydomain.com:demo:1.0.0 /data/file1.txt` |
| `install` | `install <DOM:PKG:VER>` | Downloads and cryptographically verifies a package release (supports `:latest`). | `install mydomain.com:demo:latest /data/app.bin` |
| `show` | `show <DOMAIN>:<PACKAGE>` | Walks the backward cryptographic hash chain and displays release history with signatures. | `show mydomain.com:demo` |

---

## Experimental Evaluation

The repository includes automated simulation suites to evaluate scalability and fault tolerance:

### Run Benchmark Experiments
```bash
# Execute both Scalability and Reliability benchmarks:
go run ./cmd/experiment -mode=all -lookups=25

# Or run individual modes:
go run ./cmd/experiment -mode=scalability
go run ./cmd/experiment -mode=reliability
```

### Generate Evaluation Plots
```bash
python3 scripts/plot_experiments.py
```
This produces the publication-quality graphs referenced in the lab report:
- `data/scalability_plot.png`: Lookup hop count scaling as a function of network size ($N \in [50, 1000]$).
- `data/reliability_plot.png`: Lookup success rate and probe overhead vs. packet loss ($p_{\text{loss}} \in [0.0, 0.90]$).

---

## Repository Structure

```
.
├── cmd/
│   ├── node/              # Main CLI binary and interactive shell (kadlab)
│   └── experiment/        # Automated benchmarking testbed harness
├── kademlia/              # Core DHT: RoutingTable, Kademlia protocol, UDP & Simulated networks
├── registry/              # Package Registry: Validation pipeline, Ed25519 crypto, SemVer, DNS
├── scripts/               # Plotting and diagram generation scripts
├── help/                  # Course lab specifications and design documents
├── keys/                  # Persisted domain keypairs (mounted into Docker containers)
├── docker-compose.yml     # Multi-node cluster orchestration
├── Dockerfile             # Multi-stage Alpine container build
├── Makefile               # Cluster management, testing, and attachment shortcuts
├── DEMO_GUIDE.md          # Step-by-step demonstration walkthrough for sprint review
└── Lab report.pdf         # Complete academic and architectural report
```