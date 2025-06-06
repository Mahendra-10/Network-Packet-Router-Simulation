# README for Assignment 2: Router

Name: Mahendra Bikram Shahi

JHED: mshahi2

---

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.

Some guiding questions:
- What files did you modify (and why)?
- What helper method did you write (and why)?
- What logic did you implement in each file/method?
- What problems or challenges did you encounter?

README: Assignment 2 - Router Implementation

Files Modified:

sr_router.c:

Implemented core packet handling logic including ARP and IP packet processing.

Added ICMP reply and error generation for ping, traceroute, and TCP/UDP unreachable conditions.

Modularized the router logic for cleaner and more maintainable code.

sr_arpcache.c:

Refactored the ARP request handling and retry logic.

Introduced functions to send ICMP Host Unreachable messages after timeout.

Separated responsibilities between ARP resolution, retry logic, and ICMP error generation.

sr_rt.c:

Implemented sr_lookup_rt() using longest prefix match logic to determine the best route.

Helper Methods Written:

find_interface_by_ip() (sr_router.c):

Searches for a router interface matching a given IP address.

Used to verify if a packet is destined to the router itself.

send_icmp_reply() (sr_router.c):

Sends ICMP error messages such as time exceeded or destination unreachable.

construct_icmp_error_packet() and send_icmp_error_packet() (sr_arpcache.c):

Build and send a type 3 ICMP message when ARP resolution fails.

Decouples packet construction and transmission.

send_icmp_error_response() (sr_arpcache.c):

Main entry for sending ICMP errors for host unreachable.

send_host_unreachable_icmp() (sr_arpcache.c):

Called when an ARP request has timed out, loops over all queued packets.

Logic Implemented:

ARP Handling (sr_router.c):

Processes ARP requests and replies.

Replies to ARP requests targeted at router interfaces.

Updates ARP cache and forwards queued packets on receiving a valid ARP reply.

IP Packet Handling (sr_router.c):

Processes packets destined for router or to be forwarded.

Decrements TTL and recomputes checksum.

Generates ICMP Echo Replies, Port Unreachable, Time Exceeded, and Network Unreachable messages.

ARP Cache Sweeping (sr_arpcache.c):

Periodically retries ARP requests.

After 5 attempts, destroys request and sends Host Unreachable ICMPs.

Routing (sr_rt.c):

Determines next hop using longest prefix match.

Challenges Encountered:

Ping Replies Not Reaching Client:

Initially, ICMP Echo Replies were being crafted but not sent from the correct interface or with appropriate headers.

Resolved by correctly identifying the receiving interface (iface) and ensuring ether_shost and ip_src were populated from the actual receiving interface.

Traceroute Not Working (TTL Handling):

Packets with TTL = 1 were dropped without reply.

Added logic to generate ICMP Time Exceeded replies when TTL expires.

Incorrect Route Matching:

Earlier logic used first-match; updated to use longest prefix match for correct route determination.

Host Unreachable Messages Not Being Seen by Client:

Although the router printed debug messages showing that host unreachable ICMP messages were being sent, they never reached the client.

This was fixed by correctly constructing the ICMP error packet, including proper Ethernet and IP header fields (especially ip_src and ether_shost), and ensuring the packet was sent out via the appropriate interface.

Code Duplication in ICMP Error Construction:

Refactored into helper functions to separate construction and sending responsibilities.

Improved modularity and reusability.

Memory Management:

Ensured memory allocated for temporary packets (e.g., ICMP replies) is freed after sending to avoid leaks.

Conclusion:

This assignment provided an in-depth understanding of core router operations at Layer 2 and 3. Breaking the logic into clean, modular helper functions greatly improved debuggability and reuse, especially when dealing with complex state machines like ARP and ICMP error conditions. The router now correctly handles ping, traceroute, and TCP/UDP error signaling in a robust and extensible way.