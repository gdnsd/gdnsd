# Security

Any public-facing network daemon has to consider security issues. While the potential will always exist for gdnsd to contain stupid bugs and the like, I believe this software is well above average industry security standards.  What follows here are in-depth discussion and analysis, to the best of my ability, of the security of this software.  The first section is about the code itself, the second describes known potential attack surfaces, and the third reviews the security history of the project.

## The Code

Most security issues are basically just a special category of code bug.  In that light, general code quality and verification is an important part of being secure.  To help aid my faulty human brain, I rely on a number of tools to help catch issues:

### Basics

The most basic tooling is the build system itself: the configure script supports a flag `--enable-developer` which turns on runtime assertion checking for the hundreds of assertions that are sprinkled throughout the code, and takes several other measures to enhance bug-finding at the cost of performance.  This is the flag I use constantly while developing, as it catches many mistakes early.  Production builds disable this flag, which gets rid of all the expensive checks and instead uses the assertions as optimization hints.

The configure script also turns on a huge suite of gcc/clang warnings flags.  It's impossible to have code that's warnings-free with such excessive flags on all compilers, but I try to at least keep it warnings-free on whatever compilers I'm developing with at the time (usually reasonably-modern gcc and clang).  When virtually all the reasonable warnings are turned on, a lot more proto-bugs get caught very early on.  Future TODO in this space: there's one more major, reasonable warning flag that the code isn't yet clean on: while it's clean for the sub-options `-Wsign-conversion` and `-Wfloat-conversion`, it's still not clean for the broader and more-complete `-Wconversion` yet.

The compiler/linker flags set up by gdnsd's autotools config also default to turning on all of the reasonable (as in, not horribly impactful to performance) security hardening flags I'm aware of for the GNU toolchain if they seem to be supported at build time.  This can be disabled via --without-hardening if you'd like to supply different/conflicting ones, or to aid in debugging/analysis.

### Static Analysis

For static code analysis, there are three tools I primarily rely on which have proven themselves to be pragmatic (low false positive rate, history of finding real issues for me): cppcheck, clang-analyzer, and Coverity.  I run cppcheck and clang-analyzer fairly often while developing locally, whereas the commercial Coverity scanner (which offers free scanning to open source projects like this one!) I tend to only run when I'm preparing to tag and upload a real release.  Coverity still catches a few false positives on gdnsd's code, which I've flagged and dismissed in the tool, but in the overall it's a pretty high quality checker that I highly recommend.  I've tried several other static analysis tools and found them lacking or way too noisy, but I'm always on the lookout for new ones to throw into the mix!

### Testing

This code ships with a fairly extensive regression/integration-level test suite.  Total absolute coverage numbers are weak because the testsuite doesn't cover fatal cases (in others words, if condition Foo causes the daemon to log a fatal error and immediately abort execution, the testsuite never exercises condition Foo, and gdnsd tends to have a lot of fatal conditions since we check all error outputs and user inputs...).  When fatal branches are eliminated from the dataset, we get ~80% line coverage on the rest, which is pretty decent.  The core DNS packet code (`dnspacket.c`) which handles both the parsing of network input and the generation of network output, has 100% function, line, *and* branch coverage.  Having such a testsuite at all is immensely helpful for making quality code changes in general.  Beyond that, it also forms the basis of dynamic analysis

### Dynamic Analysis

For dynamic bug-hunting, the testsuite is executed in ways that look for runtime issues in the exercised code.  My key tools here are valgrind and the compiler sanitizers available through the gcc driver: the address, leak, and undefined behavior sanitizers are all expected to execute cleanly on this code, and I try to turn on all the reasonable excess checking options I can here.

### Automation

Most of the above is automated through various scripts in the source tree's `qa/` subdirectory.  The automation is pretty weak and usually specific to my particular development environment, paths, and versions of the tools.  They may not run for everyone else everywhere else, and that's ok.

## Attack Surfaces and Risks

### The network

Being a public network daemon, the primary attack surface of gdnsd lies in the data it receives from clients over (usually public-reachable) UDP and TCP sockets.  If there's any failure in validating and handling odd network inputs, the fallout could be either denial of service (causing the daemon to crash or consume excessive resources) or a compromise of the daemon's code, which in turn could lead to a compromise of the user account the daemon runs as on the server.  Assuming the recommended model of running the daemon under a separate unprivileged user account, the scope of such compromises is fairly limited without chaining to a separate local privilege escalation bug elsewhere in the operating system.

One particular additional risk of note is that the daemon expects to have one excess privilege, which is the ability to bind port 53, and this privilege would be subject to compromise.  On FreeBSD the documented example way to give gdnsd this privilege is using `mac_portacl` rules that enable the specific port for the uid that gdnsd runs as.  For Linux it's an inherited and/or ambient `CAP_NET_BIND_SERVICE` capability for the process, which allows binding **any** privileged port.  Therefore, this is something extra to look out for in terms of risk if the daemon's code is completely compromised.

### The runtime

gdnsd doesn't expect to run with elevated privileges (i.e. does not expect to be started as the `root` user), and does not require it.  It does require the capability to bind privileged ports as mentioned above, which must be configured in a system-specific way.  Once started successfully as non-root with such capabilities, the attack surface remains constant in this regard (as opposed to, say, the typical kind of model where the daemon starts as root, spawns a `uid=0` helper process for persistent privileged operations with privilege separation, and then drops privileges in the main process).

### The control socket

The daemon also listens on a local Unix domain socket for control operations.  Access to this socket is currently restricted by filesystem permissions, and thus the init script or unit file also plays a role in securing the control socket when it creates and/or sets the permissions of the enclosing directory.  The expected access rules are that only root and processes running as the same uid as the daemon can connect to the socket successfully.  If something breaks these rules and allows other arbitrary access from the local server's unrelated processes and/or uids, it opens up local versions of the same possibilities as the above: a bug in control socket input parsing could compromise the daemon and/or cause denial of service.  Further, the control socket by its nature implicitly allows easy denial of service by asking the daemon to stop itself.

## Security History

All past versions that were stable public releases are in scope here, but bugs that existed in some commits between releases or only in beta releases are not considered in scope, as only actual release code is expected to live up to rigorous standards.  As far as I'm aware, there has never been a case where a released security flaw was found and then covered up silently.  All such flaws have been noted in the commits that fixed them and in the NEWS update of the next official release.  There's never been a CVE released that specifically affected gdnsd.  Arguably the two historical entries here should've had them, but I didn't do so at the time.  In the future, I plan to do so when it makes sense.

Notes on the general history and timeline of gdnsd stable releases that are relevant for context:

* The first public release was version 0.02, released on 2008-06-09 (it's now over 10 years old!)
* As of this writing (just before 3.0.0 in late 2018) there have been 56 stable release versions in this time
* All public stable releases, from 0.02 through the present, have seen significant public exposure as daemons on the Internet running DNS services for major production services for real users; none of the historical stable releases existed merely in some private vacuum.

On to the list itself:

* 1.0.2 - 2010-04-08 - Network-level reflective/volumetric DoS

Versions affected: presumably 0.02 - 1.0.1
CVE Assigned: No
Observed/Reported in the wild: No
Explanation: A co-worker found this while actively testing various reflective and volumetric denial of service scenarios against gdnsd-1.0.1.  Because gdnsd was sending an error response (should've ignored/dropped instead) when a query had the QR (query response) bit set, it was pretty easy to craft a spoofed packet to gdnsd to inject a reflective loop of packets that would carry on indefinitely between gdnsd and some other DNS server (including another gdnsd instance).  Because gdnsd generally handles volumetric attacks better than mainstream DNS servers, in the case that the reflection was set up between gdnsd and another vendor's implementation, the other side would generally fail first and limit the attack before gdnsd itself fell over.  That's nice for gdnsd, but it's a pretty ugly way to weaponize one daemon against another :/

* 1.10.1 - 2013-10-04 - DoS via network induced fatal error, in developer-mode builds only

Versions affected: 1.8.0 - 1.10.0
CVE Assigned: No
Observed/Reported in the wild: No
Explanation: gdnsd can be built with the configure argument ``--enable-developer``, which turns on a large number of runtime assertions that abort execution with specific log output about the failed assertion.  There was one such assertion that was faulty, and could be violated by network input with a carefully crafted, unusual packet.  The rest of the code didn't actually rely on the assumption of this faulty assertion, so in production builds (which lacked the assertion) this wasn't capable of causing a problem.  However, if one were running a non-production `--enable-developer` build of these releases exposed to the Internet (e.g. hunting for other bugs?), it could be easily killed with a single packet.  Note this wasn't a crash: the code willfully exited with a fatal error message in this case.
