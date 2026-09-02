# Additional tips, advice, and resources

## Kademlia resources

The primary source is the original Kademlia paper:
- Maymounkov, Petar, and David Mazieres. *"Kademlia: A peer-to-peer information system based on the xor metric."* International workshop on peer-to-peer systems. Berlin, Heidelberg: Springer Berlin Heidelberg, 2002.
- [https://link.springer.com/chapter/10.1007/3-540-45748-8_5](https://link.springer.com/chapter/10.1007/3-540-45748-8_5)
- [PDF](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)

The Kademlia paper leaves out some details. This page fills in some of those details:
[https://xlattice.sourceforge.net/components/protocol/kademlia/specs.html](https://xlattice.sourceforge.net/components/protocol/kademlia/specs.html)

Specifically for understanding the fully general routing tree, bucket splitting, and the `b` parameter, we have a [supplementary PDF here in the repo](kademlia_routing_tree.pdf).
However, implementing it is optional, and the simplified flat list of buckets is acceptable.

There is also an [interactive illustration](https://kelseyc18.github.io/kademlia_vis/basics).

We will also have lectures in the course where we describe DHTs in general and Kademlia specifically in more detail.

Of course, this is by no means an exhaustive list, and if you do some Googling you're likely to find a lot more resources.


## Programming language

The repository contains [starter code](kademlia/) written in the [Go language](https://go.dev/), as well as additional [tutorials for programming in Go](../tutorials/).
There is also some introductory material on Go and in particular concurrency in Go on Canvas in the "Warmup" module.

Using Go will therefore be relatively straightforward.
While we recommend that you use Go for your implementation, you are allowed to use any language you like.
We only "officially" support Go and Elixir/Erlang.
If you choose some other language, you'll be on your own, and we don't guarantee any support from our side.

In the past, almost all groups have chosen Go, and very occasionally some use Rust.
So far, groups that choose Rust tend to regret it.

In addition to the tutorials in the repo and the warmup module, you may also want to check out [this tour of the Go programming language](https://tour.golang.org/) if you are new to Go.
There is also a [list of tutorials on go.dev](https://go.dev/doc/tutorial/).

If you want to use the [GoLand](https://www.jetbrains.com/go/) IDE, you can get a student license via your LTU e-mail address.


## Containerization

While we recommend that you use [Docker](https://docs.docker.com/get-started/) for containerization, that is not a requirement.
If you use Docker, you might want to use this image as a starting point: [https://hub.docker.com/r/larjim/kademlialab/](https://hub.docker.com/r/larjim/kademlialab/).
This repo already contains a [Dockerfile](Dockerfile).

To make demonstrations and assessment run smoothly and efficiently, you should automate spinning up and tearing down the container-based test network using some script or orchestration solution.
If you use Docker, [Docker Compose](https://docs.docker.com/compose/) might be a good option, and this repo already contains a [Docker compose file](docker-compose.yml).


## Concurrency and Thread Safety

Make sure you really understand race conditions, so that you know what problem it is you are trying to solve.
Think carefully about which parts of the code are run by more than one thread (or goroutine) and, in particular, which variables/data structures are accessed by different threads.

You can use old-fashioned locks to control access to critical regions.
That's a perfectly valid solution and perhaps one you are familiar with and find natural to think about.
However, there are other options, especially in Go, which has *channels* built into the language.
For example, one option is to let only a single goroutine have access to a particular data structure, and then other goroutines communicate with it using channels.
If you get used to this way of thinking, you may find this solution to be **simpler** than locks!

Either way, you can run your tests with the `-race` flag (see documentation: [Data Race Detector](https://go.dev/doc/articles/race_detector)).
This will instrument your code so that race conditions can be detected automatically.
**However**, how helpful this is depends on how good your tests are.
If there are race conditions that your tests never touch, then they will not be detected.
The race detector is designed to never have false positives.
(Running with `-race` is a dynamic rather than static analysis!)

Again, some introduction to concurrency in Go can be found both in the tutorials and the "Warmup" module in Canvas.


## Implementing the general routing tree

If you are interested in implementing the general routing tree, you might want to check out the [supplementary explanation in kademlia_routing_tree.pdf](kademlia_routing_tree.pdf) in the repo.
It expands on sections 2.4 and 4.2 of the original paper.


## Testing

While achieving a test coverage of at least 80 % is a requirement, we strongly suggest not treating it as a separate task to work on.
That is, **don't implement first and then add tests at the end!**

First of all, achieving the mandatory coverage will be much more difficult if you add tests after finishing the implementation.
Second, your tests should help you get the implementation working in the first place!
So, look at the tests as a tool to help you rather than a box to tick.
In fact, if you write tests in parallel with the implementation, then attaining the required coverage should not require much effort.

You can read more about code coverage in Go here: [https://blog.golang.org/cover/](https://blog.golang.org/cover/).
Your favorite IDE or editor plugin for Go almost certainly has built-in support for test coverage as well.

Here is a brief tutorial on how to add and run tests: [https://go.dev/doc/tutorial/add-a-test](https://go.dev/doc/tutorial/add-a-test).
See also the [tutorials in this repo](../tutorials/) and the test cases already in the starter code.


## Organizing your work

The course has three checkpoints where you present your progress so far.
While we call them "sprints" and "sprint reviews", we do not impose any sprint structure.
For our purposes they are simply deadlines.
You are welcome to run them as real sprints within your group if you find that useful.
How you organize yourselves is entirely up to you, and we will not enforce or assess your adherence to a method.
We will not inspect your backlog, measure your velocity, or assess your retrospectives.

Most of you have already encountered [agile methods](https://en.wikipedia.org/wiki/Agile_software_development) in earlier courses, so we will not reintroduce them here.
Instead, here are two pieces of advice specific to this assignment.

**Get the lookup algorithm working early.**
Kademlia is unusually interconnected.
Joining the network, storing a value, and retrieving a value are all built on the same node lookup procedure.
Since everything else depends on it, you do not want to build all the surrounding infrastructure first and only finish lookup at the end,
because then, in the best case, you are at 0 % end-to-end functionality for 90 % of the time and then finally jump from 0 % to 100 % functionality at the end.
That is, it's a risky all-or-nothing approach, with all the integration concentrated near the deadline, and with no meaningful iteration.

Fortunately, there are corners you can legitimately cut in order to get there sooner.
The routing table does not need to be a proper set of buckets with eviction and refresh: a flat array of contacts that you sort by distance answers the same question, *which `k` contacts closest to this target do I know of?*
The lookup algorithm does not need to send parallel probes either — starting with `alpha = 1` is much simpler and still gets the iterative narrowing right.
The data store is not needed at all, since node lookups never touch it.
Neither is periodic replication, nor the CLI.

These are safe shortcuts because of one specific property: when you later replace them with the real thing, the code around them does not change.
The behavior does differ slightly (a flat array never evicts anything, and `alpha = 1` needs more rounds and copes worse with packet loss) but nothing you have built on top has to be rewritten.

**But implement the general case, not the case in front of you.**
A group that struggles to make one node join the network, and then has to struggle just as hard to make a second node join, has not implemented joining.
It has hardcoded a scenario.
If joining works at all, it should not matter whether 1, 2, or 117 nodes join.
The same goes for lookups, replication, and bucket maintenance.

The difference between these two pieces of advice is worth being precise about.
A shortcut is safe if replacing it later does not force you to rewrite the code around it.
Making the two-node case work by special-casing it fails that test: the code around it was written against a scenario rather than a mechanism, so the next case you add breaks the previous one and the effort does not accumulate.


## Suggested progression

Here is a rough guideline for the approximate progress we expect for the different sprint reviews:

**Sprint 1**:
- A working understanding of the Kademlia algorithm.
- Setting up containerization.
- Simulated network.
- The lookup algorithm should be implemented (at least assuming some simplifications such as a fake routing table and sequential (i.e. `alpha = 1`) lookup).
- Test coverage should already be around the target 80 %. (This should basically be an invariant.)

**Sprint 2**:
- Part 1 should be more or less complete.
- You should have started on the report, which should contain some meaningful design decisions at this point, and possibly some experimental results.

**Sprint 3**:
- Since this is the final sprint, all mandatory requirements in parts 1 and 2 must be complete at this point.
- The report must be finished and uploaded to Canvas.

Note that part 2 largely uses what you built in part 1 as infrastructure.
Part 2 should therefore take significantly less time compared to part 1.


## Experiments and Measurements

One important aspect to keep in mind is that running thousands of nodes communicating over a simulated network and all logging events may be limited by the throughput of the logger.
This may impact how meaningful wall-clock time measurements are.
So, if you measure "time" in any experiments, this needs to be taken into account.
Either you have to find a different way to measure time, or you have to make a convincing case for why the wall-clock time measurements are meaningful.

Also, if you initially take shortcuts, such as a fake routing table that ignores the standard maintenance rules or sequential rather than parallel lookup, don't base your final results only on them.
However, it would be perfectly fine to measure both the fake implementation and the real implementation and compare them.


## Libraries

The lab specification allows you to use libraries freely, except those that implement RPC for you.
Why are RPC libraries restricted? There are multiple reasons:
- Communication, RPCs, network failures (lost/reordered packets), idempotence, etc. are all important concepts in this course, and outsourcing core functionality such as correlating request and response, timeouts, and retry policies to a library is a missed learning opportunity.
- Experiment 2 is directly influenced by your timeout/retry policies. So you need to at the very least understand it in detail and potentially need to be able to control it, which may be difficult if it is hidden in a library.

In addition, some popular libraries, such as gRPC, have no or only experimental support for using UDP as the transport protocol.

Again, using libraries for serialization is fine. The standard library (e.g. `encoding/json`) should be sufficient, but you could also use [protobuf](https://protobuf.dev/).


## Report

The instructions say that the report needs to include "a system architecture description that also contains an implementation overview".
A common question is what this should look like.
Ultimately, the point is that you are supposed to communicate to someone how your system is designed.
What are the main components, and how do they communicate with each other, etc?
Just like you have to make choices about what the best way is to design and implement your solution, you have to make choices about what the best way is to communicate to someone else what you have done and why.

Try this: imagine that we change the assignment so that the students next year will get your implementation as a starting point and are asked to improve it, such as adding features.
*What information would they need so they quickly understand your implementation and can start modifying it?*
*What design choices should they be aware of?*


## Package/value size

What happens if you try to up-/download a package that is, say, 10 MB in size?
Well, it cannot fit in one UDP datagram.
Some possible approaches:

1. **Easy:** Impose an artificial size limit.
2. **Recommended:** Separate control and data planes so that UDP is used in the control plane for RPCs, while TCP is used only for the data plane to do the actual value transfer.
3. Handle fragmentation across multiple UDP datagrams.
4. Break values into chunks and always store packages as multiple chunks rather than a single complete value. (Also quite complex but moves the fragmentation to storage rather than networking.)

Option 1 is the simplest and most straightforward, but it is also the least satisfying, because then we can't handle the general case and have to pretend that we can handle packages of arbitrary size.
If you choose to impose a size limit, it has to be large enough that simple test cases still work (some silly limit like 2 bytes would interfere with testing/demonstration).
That's why we impose the arbitrary minimum specified in [LAB-SPEC](LAB-SPEC.md).

Option 2 is not much more difficult than option 1 and is almost as nice as options 3 or 4. So this is the recommended solution.

Option 3 is quite a bit more complex, especially when considering packet loss, and the advantage over option 2 is minimal.

Option 4 is a nice option. It is also quite complex compared to options 1 and 2, but less complex compared to option 3, and it moves the fragmentation to storage rather than networking, which is a much nicer place to handle it. It also has some additional advantages, such as better load balancing. However, the main reason for not choosing this as the recommended option is that it interacts with part 2.
