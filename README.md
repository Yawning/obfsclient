## obfsclient  - A C++11 obfs2/3 Tor managed pluggable transport client
#### Yawning Angel (yawning at schwanenlied dot me)

> Compile this if you are a obfuscated strong proxy
> who don't need no Python

### What?

This is a C++11 client implementation of the following protocols:

 * [obfs2](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/blob/HEAD:/doc/obfs2/obfs2-protocol-spec.txt) - The Twobfuscator
   * The shared secret mode is not used in the wild and is unsupported.
 * [obfs3](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/blob/HEAD:/doc/obfs3/obfs3-protocol-spec.txt) - The Threebfuscator

By design will only function as a ClientTransportPlugin for Tor.  It does use a
reasonably complete implementation of the Pluggable Transport spec so when used
properly, it will function as a drop in replacement for asn's Python
implementation.

### Building

It currently has the following external dependencies:

 * Compile time only
   * CMake (This can be changed out by an enterprising programmer)
   * Doxygen (For the documentation)
   * [Google C++ Testing Framework](https://code.google.com/p/googletest/)
     * A copy is included under src/gtest, so there should be no reason to
       install this.
 * [libevent2](https://www.libevent.org)
 * [OpenSSL](https://www.openssl.org/)
 * [liballium](https://github.com/Yawning/liballium)

My CMake-fu is weak so you will more than likely have to edit the CMakeLists.txt
in the root directory for this to actually compile.  Apart from that it builds
just like any other project.

Make Targets:

 * all - Build the obfsclient binary and obfsclient_test
 * test - Run obfsclient_test (Better output if you run it manually)
 * doc - Build the doxygen documentation

### Usage

In your torrc:

    UseBridges 1
    Bridge obfs2 ip:port fingerprint
    Bridge obfs3 ip:port fingerprint
    ClientTransportPlugin obfs2,obfs3 exec /path/to/the/binary/obfsclient

### Implementation notes

Like the rest of my C++ code, C++ exceptions and RTTI are not used, and it is
expected that the appropriate compiler flags are passed in to disable these
functions.  The obfsclient binary will assert() on fatal errors (out of memory),
because that's realistically the only safe thing to do.

Caveats:

 * My UniformDH implementation is not constant time.  I do not view this as a
   huge problem, since neither is the the Python implementation in production
   today, and the cryptographic components for obfs3 are intended as
   obfuscation.
 * The UniformDH implementation is glacially slow.  I may be spoiled by using
   Curve25519 so much lately.
 * IPv6 is unsupported, even though it could be if I used SOCKSv5.
 * There is no pushback between the incoming/outgoing sockets, so congestion
   feedback from the bottleneck link will not get propagated.  While this is
   trivial to fix, the official client does not appear to do this either.

### TODO (Patches accepted!)

 * Logging would be nice (Maybe?  It Just Works (TM)).
 * A connection timeout.
 * Assuming people actually want to use this, add support for scramblesuite.
 * The build system sucks.

### WON'T DO

 * No, I do not care if this compiles out of the box on Windows.
 * No, I do not care that this doesn't compile with ancient compilers.
 * Unmanaged mode might be a nice to have, but all I care about is Tor.
 * Server implementations of all the protocols (Use the Python version).
