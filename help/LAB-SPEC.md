# Lab specification

We start with the technical details.
Administrative details, such as deliverables and how the assignment is assessed, appear at the bottom.


## Part 1 - Kademlia

In part 1, you implement the Kademlia DHT.
It is a distributed Key-Value (KV) store that maps keys to values.
We will be able to store any arbitrary data, but, in the system we are building, the point is to store software packages/libraries such as .jar files etc.
So the system is designed for storing binary blobs.
However, for testing/demonstration purposes, we can choose to store plain text so the data can easily be inspected.

The keys are opaque `B`-bit identifiers that could in principle be arbitrary.
(We will use `B = 256` bits, but the specific value is not very important.)
However, we will assume (and enforce) that a key is the cryptographic hash of the corresponding value.
So, for example, for some blob `V`, the key is `K = hash(V)`.
(With `B = 256` the SHA-256 hash function is a suitable choice for computing the key.)
In other words, `hash(V)` maps to `V`.
(Although, we will introduce specific exceptions to this rule in part 2.)

This makes the data *"content-addressable"* and *self-verifying*.
That is, a client that obtains a value `V` when looking up a key `K` can check that `K = hash(V)`.
Since we assume that cryptographic hash functions (such as SHA-256 etc.) are collision-resistant and pre-image attacks are computationally infeasible, if the hash matches, the value is almost certainly correct.


### Requirements

You should essentially implement Kademlia as described in the original paper.
Unless stated otherwise below, assume that you are to build what the paper describes.

#### Protocol

The following list clarifies/emphasizes some of the requirements but is not exhaustive:

- Use UDP for Remote Procedure Calls (RPCs), not TCP. However, you *may* use TCP **for value transfers** *if you make a control/data plane separation* (see [TIPS](TIPS.md) for an explanation).
- During lookups, `alpha` probes must be sent in parallel, but exactly how to parallelize is up to you. ([This specification](http://xlattice.sourceforge.net/components/protocol/kademlia/specs.html) elaborates on this point and explains three different approaches. Choose one of them.)
- While the paper calls the lookup algorithm recursive, the algorithm is actually iterative. Implement it as described (i.e. iteratively).
- Implement the full joining procedure, *including the bucket refresh*.
- Your implementation must be able to
    - join a network by contacting a bootstrap node already in the network
    - store new key-value pairs
    - periodically replicate existing key-value pairs so that they are not lost *despite churn*
    - look up nodes (with IDs "close" to a key/ID)
    - find a value by looking up its key (hash)
    - correctly maintain the routing table.


**Changes and additions** relative to the Kademlia paper:

- Use `ID = hash(IP|port)` as the node ID.
- Nodes reject a request to store a mapping `K ↦ V` iff `K != hash(V)`. In other words, they accept a `(K,V)` pair iff `K = hash(V)`.
- Similarly, when a node (acting as a client) looks up a value `V` for a key `K` it must check that `K = hash(V)`. If they do not match, it must discard the value and report (print/log) an error.
- RPC responses must be unambiguously matched to the corresponding request. In addition, an attacker who cannot observe the request must not be able to forge a plausible response.
- Your system must either handle values of arbitrary size or impose an explicit size limit. **If** you impose a size limit, you must document the limit and explain it. (And the limit must be *at least* 255 bytes.)

**Required omissions** relative to the Kademlia paper:

- _Do **not** implement expiration._ The Kademlia paper says that the time-to-live is updated when a value is requested and that the original publisher must periodically re-publish a value to keep it alive even though nobody is requesting it. But for a package registry, we do not want any kind of expiration. (The periodic replication ensures that values are not lost despite churn.)


Simplifications and **permitted** omissions:

- You are **not required** to implement the fully generalized routing tree with bucket splitting. In other words, fixing the parameter `b = 1` so that you end up with a list of `B` buckets is OK.
- You are **not required** to cache value lookups along the lookup path.
- You are **not required** to consider "caravan effects".
- Values are **not required** to be persisted to disk and *may* be lost when the node terminates/restarts (e.g. when using Docker containers). This includes
    - Values downloaded from the network.
    - A node's data store of key-value pairs.

If you choose to allow `1 <= b <= B`, the branching parameter `b` must be freely adjustable, and you must have test cases that clearly demonstrate the correct behavior of the tree, in particular that buckets are split correctly for a given value of `b`. See the [TIPS](TIPS.md) for more details.

Parameters:

- `B = 256` - key/ID space
- `alpha = 3` - lookup parallelism (default, **must be adjustable**)
- `k = 10` - replication factor (default, **must be adjustable**)

Note that `k = 10` is lower than what the paper suggests (20) because we will have a relatively small network.


#### Engineering

These requirements have less to do with *what* you implement and more *how* you implement it.

- You must hide network communication behind an abstraction so that you can test the system with a simulated network and control latency and packet loss. (One of the tutorials on the course GitHub repo shows how to do this.)
- Your test suite must include test cases that run **at least 1000** node instances that communicate over your simulated network.
- You must achieve a test coverage of at least 80 %.
- You must set up containerization (e.g. Docker) so that you can spin up a network with at least 50 nodes (each running in its own container) on a single computer.
- You must achieve a minimum level of thread safety: your test suite must not produce any errors (e.g. race conditions) when run with the `-race` flag.
- Parameters (such as `alpha`, `k`, and the replication period) must be easily adjustable. (Requiring recompilation is fine.)
- You may freely use libraries for e.g. serialization, CLI, testing, data analysis, containers, crypto, etc., **except for RPC**. Request/response correlation, timeouts, and retransmission must be your own design and implementation.
- You must add instrumentation for collecting data that you will include in your report.
    - **At a minimum, you must log**
        - probes sent during node/value lookups
        - lookup success/failure.
    - **Examples** of additional events you may **optionally** choose to log:
        - Routing table eviction.
        - Dead (unresponsive) node detected.

Note that you are expected to be able to run your system in two modes:
- Multiple instances in the same process using the simulated network for larger-scale scenarios (1000+ nodes).
- Containerized for small-scale scenarios (50 nodes) to check that the system would work if deployed on a real network.

**If** you separate control and data planes, only the control plane needs to be simulated.
That is, the packet loss parameter applies only to the UDP RPCs, and you may treat the TCP data plane as a reliable channel.
*It should still sit behind the network abstraction*, so that value transfers work in the in-process simulated runs (since real TCP connections are not practical at 1000 nodes) and so that the transfer code is covered by your tests.
Value transfers can of course still fail for other reasons, such as the remote node leaving the network, meaning churn stays relevant.


#### User Interface

Implement a user interface in the form of a CLI/shell that you can use for demonstrations to control a node.
You may implement the user interface either using sub-commands (e.g. using the cobra package in Go) or an interactive command shell.
The choice is yours.
The following commands must be supported:

- `ping IP:PORT` -- ping a node. If you want to be cool, also allow pinging by ID (looking up the IP:port in the routing table, possibly (even cooler) by any unique ID prefix). *Prints the round-trip-time if successful.*
- `put FILENAME` -- upload the contents of a file (a value) under its hash (the key). *Prints the key of the value.*
- `get KEY [FILENAME]` -- download the value associated with the key (as a hex string representation of a hash) and save it to the specified filename or print it if no filename is given. *Prints the node it was received from if successful.*
- `exit` -- terminate the node.
- `show rt` -- print the routing table in an appropriate, human-readable format (useful for debugging and demonstration).
- `show ds` -- print the data store, i.e. which keys are stored (useful for debugging and demonstration).

<!--
TODO: consider adding additional requirements for `get` so that it handles both binary blobs and text gracefully and always outputs some generally useful information. (E.g. confirmed key/hash, size, whether text or binary blob, etc.)
-->

Make sure the debugging (`show`) commands produce concise and useful information. (For example, with 256 buckets, most of them will be empty and should be skipped in the output. And IDs/keys will be 64-digit numbers in hexadecimal and should therefore be truncated, e.g. showing the first and last 4 hex digits.)
You are encouraged to add additional (sub-)commands and/or additional (optional) flags and parameters to facilitate testing/demonstration.


#### Experimental Evaluation

Your report will present results for at least two experiments.
You collect the data by logging events (as discussed above under the instrumentation requirement) and analyzing the log with a simple, external script.
You may use any language for the script (which is exempt from the code coverage requirement).
Make the log entries simple and structured, i.e. machine readable without requiring unnecessarily complex parsing.

Basic methodology rules:
- Randomly generate a network topology (i.e. different IP:port combinations so we get different node IDs)
- Randomly generate key-value pairs
- Make runs repeatable by explicitly setting the RNG seeds.
- Repeat the experiment for each configuration (different parameters) with multiple seeds.
- Report variance along with an average.
- Explain the experimental setup. In particular, how were things measured? Why should we believe those measurements are meaningful?
- Explain what results we should expect *and why*. Compare the observed result to the expectation and discuss (i.e. try to explain) any deviations.

**Mandatory experiments:**
- Lookup scalability as a function of the network size `N`:
    - Plot the number of probes needed during lookups as a function of `N`.
    - Compare to the expected number of probes/"hops".
- Lookup reliability (success rate) as a function of packet loss probability.

**Examples** of additional **optional** experiments:
- Time between request and response as a function of packet loss and/or latency.
- Number of lookup probes and time required for lookups as a function of `alpha` (particularly important to discuss what we should expect).
- Lookup reliability as a function of churn rate. (Requires that you can control the churn rate, i.e. when nodes join/leave the network.)
- Lookup reliability as a function of the replication factor `k`.

Note that some of these experiments are affected by your RPC timeout/retry policy (i.e. how long you wait for a response and whether/how often you retry), which is therefore important to document clearly.


## Part 2 - Package Registry

In part 2, we build additional functionality on top of the data store developed in part 1.
As in part 1, this document focuses on the requirements.
The design itself is explained separately in [PART2-DESIGN](PART2-DESIGN.md) (just like part 1 outsourced the actual system design to the Kademlia paper and other resources).

Nodes must
1. Accept only package publications by the domain owner (i.e. update the latest-version pointer for a package in the domain).
2. Refuse to fork history (i.e. not fork the chain/linked-list of version records).
3. Refuse to roll back updates (updating the latest-version pointer to an older version record).
4. Catch up when they detect that they have fallen behind (i.e. that they must have missed some version update).

You are encouraged to set up DNS on your test network such that your nodes can make actual DNS queries.
However, you are also allowed to fake the DNS-based ownership verification.
(You probably want to hide the verification behind an interface anyway.)

Versions could be simple integers or `major.minor.patch` (semantic versioning), or even something else.
The important requirement is that they have a total order.

The choice of signature scheme (e.g. ED25519 or RSA) and how to encode the PK in the TXT record are up to you.
Clearly document your choices.




### User interface

We need a user interface similar to the one in part 1. The following commands must be supported (**in addition to the commands from part 1**):

- `publish [--force] [--prev=PREVIOUS-VERSION] DOMAIN:PACKAGE:VERSION FILENAME` - publish the package stored in `FILENAME`
- `install DOMAIN:PACKAGE:VERSION` - download the specified version (which may be "latest") of the specified package
- `show DOMAIN:PACKAGE` - show the version chain of the specified package
- `show dns DOMAIN` - show the PK of the owner of `DOMAIN` (if any)

We need the `--force` flag for testing/demonstration.
Without the `--force`, your program should check that the new version is valid relative to previous versions (before attempting the upload).
With `--force`, those checks are ignored, and the node happily attempts to make an invalid version update (which other nodes should of course reject).
By default, `publish` uses the appropriate previous version of the package (which is none when publishing the first version).
The optional `--prev=PREVIOUS-VERSION` specifies the previous version explicitly.
(`--force` and `--prev` can be combined to *attempt* to create invalid updates like forks, cycles, roll-back.)

For `show dns DOMAIN` it doesn't matter if you are doing actual DNS lookups or if you are faking it. What matters is that you can show what the node believes about domain ownership.

Now `show ds` should interpret and (concisely) show version records (and latest-pointers), not just key hashes.


### Engineering

The requirements from part 1 still apply, e.g.:
- 80 % test coverage
- Test cases with 1000+ nodes on the simulated network
- etc.


## Report

One of the mandatory requirements is a written report about your implementation.
It must contain the following:
- Your group number.
- The names of all group members.
- A link to your code repository. (If private, remember to invite us first!)
- Which libraries you used and why. (Particularly anything close to the RPC layer.)
- A system architecture description that also contains an implementation overview.
- A description of your system's limitations and what possibilities exist for improvements.
- If you went beyond the minimum requirements, document and explain how/why.
- You must explain how you have ensured thread safety. (For example, where are the critical regions and how did you protect them?)
- Experimental setup and results. (Refer to the "Evaluation" section above for details on what this must cover.)

There is no fixed template.
Most of you will be used to writing technical reports at this point.
Remember, the whole point is to communicate an idea to another human being.
No template can automatically accomplish that for you.
How do you tell someone concisely and clearly what you have done, what questions your experiments try to answer, what answers you found, and why someone should believe those answers?


## Assessment

Your work on the assignment will be assessed during three "sprint reviews".
See Canvas for deadlines.
You must sign up for each sprint review.
The signup sheets are also on Canvas, e.g. `Assignments/Sprint 1`.

Note that during assessment, each group member is expected to be able to demonstrate every requirement, as well as describe how and why you approached it the way you did.

By the last sprint, you must have completed all mandatory requirements, including the report (which must be uploaded in Canvas prior to the sprint review).
In the first sprint, we will specifically check your understanding of Kademlia.
Members of the group will be selected at random to answer various questions about Kademlia.
We will also check that you have managed to set up containerization and that nodes (containers) are able to communicate.
In sprint 3 (at the latest), you are expected to be able to answer questions about the design of part 2 (such as the questions posed at the end of [PART2-DESIGN](PART2-DESIGN.md)).
Other than that, how you distribute your work across the sprints is up to you.
See the [TIPS](TIPS.md) for a rough suggestion.
