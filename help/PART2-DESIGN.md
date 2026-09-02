Given that we have a DHT where we can store arbitrary key-value pairs, how can we use it to build a decentralized package registry?

In part 1, anyone can upload any key-value pair. They are just arbitrary blobs.
There's no concept of ownership or authenticity.
Now we want to have a little bit more structure.
Each package can exist in different versions, and we want to keep track of the latest version.
We also want to be able to find packages based on a nice descriptive name rather than an opaque hash.

But as soon as we allow values to be associated with names (rather than their hash) they stop being content-addressable and we can have collisions.
It would be nice to have some namespaces so that package names don't collide.
But then how do we make sure the namespaces don't collide?
There must be some restriction on which namespaces different participants are allowed to use, so that, if I'm using namespace "X", it's already taken and nobody else can use it.
And that implies more concretely that we need to make sure that I am the only one that can upload packages under "X".
(Otherwise, what would it mean to say that "nobody else can *use* it"?)

Well, we could outsource that to DNS and use actual domain names.
Then the namespace has an actual, real-world owner because the domain name has an actual, real-world owner.
Mechanisms for acquiring and enforcing ownership already exist, and all we have to do is verify ownership claims using the existing DNS infrastructure, i.e. treating DNS as an oracle.
If someone shows up with a public key (PK) and claims to own "example.com", we can for example require that they have placed PK in a DNS TXT record for "example.com".
Whoever this person is, they clearly own that domain, or at least have the authority necessary to change its DNS records.
And if they sign something (e.g. a package) with the corresponding secret/private key (SK), we know it was signed by the owner of the domain.

That also helps with the authenticity problem.
Now we can know that "some-domain:some-package:version" must have been uploaded by the owner of "some-domain" rather than some imposter.
(Though we will have to do a bit of work to make sure we can actually rely on that!)


We want to keep as much data as possible immutable, including the package blobs, so older versions are available and unchanged forever.
But how do we tie a blob to a package name and domain name in such a way that we can enforce ownership and authenticity?
The blobs themselves are still self-verifying (and content-addressable) because we can check that the hash of the value matches the key.
But that is always true whenever **any** value is uploaded under its hash.
It's not enough to establish authenticity.

What we'll do is upload the package blob under its hash as in part 1, and then we'll also upload a *version record* for each version of the package as well.
So, each version of the package will have a version record of the form `{tag="version-record", domain-name, package-name, version, blobHash, previous-version-record, sig}`, where `sig = sign(SK, hash({tag="version-record", domain-name, package-name, version, blobHash, previous-version-record}))`.
That is, the signature is on the hash of the rest of the version record (excluding the signature), generated using the secret/private key (SK) corresponding to the PK that owns `domain-name`.
The `blobHash` is the hash of the binary blob for this version of the package.
The record itself is stored normally, i.e. as `hash(versionRecord) -> versionRecord` (content-addressable).
The `previous-version-record` is the hash of the version record for the previous package version (or 0...0 if this is the first version).

If we know a version record, we can find the hash of the package blob for that version in the record and then look up the actual binary.
And if we only know the hash of the version record, we can look up the actual version record (and then the binary).
So, again we can get the package binary.

Note that the domain name is part of the version record, and the DNS TXT record can be used to find the owner's PK.
If that PK validates the signature, we know that the corresponding SK was used to sign the record, which means we know the domain owner made the signature.
Since the blob hash is part of what is being signed, the owner has implicitly signed the blob itself as well.
So we know that the version record was legitimately created and what the hash of the binary for that version is.
And when we look up the binary, we can check that the hash matches and "know" that the binary is what the domain owner uploaded.
(I say "know" because we're dealing with probabilities and relying on standard cryptographic assumptions.)

Because each version record has a reference back to the previous version, we can find all older versions by following the chain back, much like a linked list.
Then the question is where we get a version record or its hash.
And, in particular, we're interested in the version record for the latest version.
(Either we specifically want the *latest* version, whatever it happens to be, or we want some specific (older) version, which we can always find by starting with the most recent version.)

We will have a single special version record pointer as an entry point to enable finding the **latest** version record, i.e. the "head" of the chain.
It has a *special key* and is the only key-value pair that is mutable (so that "latest" can point to a new version record).
The key is `hash("domain:package:latest")`, where `domain` is the domain name, e.g. "rfin.ch", `package` is the package name, e.g. "java-pair", and `latest` is just the literal string "latest".
The value contains a reference to the latest version record and has a similar structure as a regular version record:
`{tag="latest-pointer", domain-name, package-name, version, versionRecordHash, sig}` (where `sig` is again the signature of the hash of the rest of the record).

So this is the only exception to the rule that a key-value pair `(K, V)` is immutable and `K = hash(V)`.
In fact, both parts of the rule must necessarily be broken together.
Because we want the name/key to be the same even when the version (and therefore the actual binary) changes, the key must point to different values over time (so it is mutable) and must be independent of the value (or the key would change when the value changes), and the key therefore cannot be the hash of the value.


## Some questions for you

Now, clearly not all possible version records we could create are valid.
But when exactly are they valid or not?
Similarly, not all updates to the "latest" version record are valid.
How do we know whether an update is valid?
And how do we even know an "update" is happening in the first place?
Why is the latest-version-record-pointer a structured value rather than just the hash of the version record for the latest version?
And why does it redundantly repeat the domain, package name, and version?
Why do we need strictly increasing versions rather than arbitrary versions such as "final", "improved", "beta", etc?

These questions are relatively straightforward, and we leave them for you to figure out, or at least to make an attempt at figuring it out.
We will of course help you out if necessary!
