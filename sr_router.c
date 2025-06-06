
/**********************************************************************
 * file: sr_router.c
 *
 * Description:
 * This file contains the core packet-handling logic for the router.
 * The refactored sr_handlepacket function processes incoming Ethernet
 * frames, delegating to specialized functions for ARP and IP packets.
 * ICMP responses, forwarding, and ARP resolution are handled modularly.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/* Function declarations for routing table lookup and ARP cache sweeping */
struct sr_rt *sr_lookup_rt(struct sr_instance *sr, uint32_t ip); // Looks up routing entry for an IP
void sr_arpcache_sweepreqs(struct sr_instance *sr);             // Periodically checks ARP requests

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/* Forward declarations for helper functions */
static void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface);
static void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, const char *interface);
static void process_arp_request(struct sr_instance *sr, uint8_t *packet, struct sr_if *iface, const char *interface);
static void process_arp_reply(struct sr_instance *sr, uint8_t *packet);
static void process_ip_for_us(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, const char *interface);
static void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *in_iface, const char *in_interface);
static void send_icmp_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, const char *interface, uint8_t type, uint8_t code);
static struct sr_if *find_interface_by_ip(struct sr_instance *sr, uint32_t ip);

/*---------------------------------------------------------------------
 * Method: sr_handlepacket
 * Scope: Global
 *
 * Main entry point for packet processing in the router. Called whenever
 * a packet arrives on an interface. Validates the packet, determines its
 * type (ARP or IP), and delegates to appropriate handlers.
 *
 * Parameters:
 * - sr: Pointer to the router instance (contains cache, interfaces, etc.)
 * - packet: Raw Ethernet frame buffer (lent, not to be freed here)
 * - len: Length of the packet in bytes
 * - interface: Name of the receiving interface (lent, not to be freed)
 *
 * Returns: None (void)
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    // Validate inputs to prevent crashes or undefined behavior
    assert(sr && "Router instance must not be null");
    assert(packet && "Packet buffer must not be null");
    assert(interface && "Interface name must not be null");

    // Log packet receipt for debugging
    printf("*** -> Received packet of length %d on interface %s\n", len, interface);

    // Ensure packet is at least the size of an Ethernet header
    if (len < sizeof(sr_ethernet_hdr_t)) {
        printf("Packet too small to contain Ethernet header (%u bytes, need %zu)\n", len, sizeof(sr_ethernet_hdr_t));
        return;
    }

    // Extract Ethernet header and type
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    uint16_t ethtype = ethertype(packet);

    // Retrieve the receiving interface details
    struct sr_if *iface = sr_get_interface(sr, interface);
    if (!iface) {
        printf("Interface %s not found in router’s interface list\n", interface);
        return;
    }

    // Log interface IP for tracing packet flow
    printf("Interface IP: %u.%u.%u.%u\n",
           (ntohl(iface->ip) >> 24) & 0xFF,
           (ntohl(iface->ip) >> 16) & 0xFF,
           (ntohl(iface->ip) >> 8) & 0xFF,
           ntohl(iface->ip) & 0xFF);

    // Dispatch based on Ethernet type
    switch (ethtype) {
        case ethertype_arp:
            handle_arp_packet(sr, packet, len, iface);
            break;
        case ethertype_ip:
            handle_ip_packet(sr, packet, len, iface, interface);
            break;
        default:
            printf("Unknown Ethernet type %04x, dropping packet\n", ethtype);
            break;
    }
}

/*---------------------------------------------------------------------
 * Method: handle_arp_packet
 * Scope: Static (file-local)
 *
 * Processes ARP packets (requests or replies) received by the router.
 * Delegates to specific handlers based on ARP operation type.
 *
 * Parameters:
 * - sr: Router instance
 * - packet: Raw Ethernet frame containing ARP packet
 * - len: Packet length
 * - iface: Receiving interface structure
 *---------------------------------------------------------------------*/
static void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface) {
    printf("Received ARP packet\n");

    // Ensure packet includes ARP header
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        printf("Packet too small for ARP header (%u bytes, need %zu)\n", len,
               sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        return;
    }

    // Extract ARP header
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t arp_op = ntohs(arp_hdr->ar_op);

    // Log ARP details
    printf("ARP operation: %d\n", arp_op);
    printf("Target IP: %u.%u.%u.%u\n",
           (ntohl(arp_hdr->ar_tip) >> 24) & 0xFF,
           (ntohl(arp_hdr->ar_tip) >> 16) & 0xFF,
           (ntohl(arp_hdr->ar_tip) >> 8) & 0xFF,
           ntohl(arp_hdr->ar_tip) & 0xFF);

    // Handle ARP operation
    if (arp_op == arp_op_request) {
        process_arp_request(sr, packet, iface, iface->name);
    } else if (arp_op == arp_op_reply) {
        process_arp_reply(sr, packet);
    } else {
        printf("Unsupported ARP operation %d, dropping packet\n", arp_op);
    }
}

/*---------------------------------------------------------------------
 * Method: process_arp_request
 * Scope: Static
 *
 * Handles ARP requests by checking if the target IP matches one of our
 * interfaces. If so, sends an ARP reply to the requester.
 *
 * Parameters:
 * - sr: Router instance
 * - packet: Raw Ethernet frame with ARP request
 * - iface: Receiving interface
 * - interface: Name of the receiving interface
 *---------------------------------------------------------------------*/
static void process_arp_request(struct sr_instance *sr, uint8_t *packet, struct sr_if *iface, const char *interface) {
    printf("Processing ARP request\n");

    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *target_iface = find_interface_by_ip(sr, arp_hdr->ar_tip);

    if (!target_iface) {
        printf("Target IP %u.%u.%u.%u does not match any interface, ignoring ARP request\n",
               (ntohl(arp_hdr->ar_tip) >> 24) & 0xFF,
               (ntohl(arp_hdr->ar_tip) >> 16) & 0xFF,
               (ntohl(arp_hdr->ar_tip) >> 8) & 0xFF,
               ntohl(arp_hdr->ar_tip) & 0xFF);
        return;
    }

    printf("Target IP matches interface %s, sending ARP reply\n", target_iface->name);

    // Allocate and construct ARP reply
    size_t reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *reply = malloc(reply_len);
    if (!reply) {
        fprintf(stderr, "Failed to allocate memory for ARP reply\n");
        return;
    }

    sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply;
    sr_arp_hdr_t *reply_arp = (sr_arp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));

    // Ethernet header
    memcpy(reply_eth->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, target_iface->addr, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_arp);

    // ARP header
    reply_arp->ar_hrd = htons(arp_hrd_ethernet);
    reply_arp->ar_pro = htons(ethertype_ip);
    reply_arp->ar_hln = ETHER_ADDR_LEN;
    reply_arp->ar_pln = 4;
    reply_arp->ar_op = htons(arp_op_reply);
    memcpy(reply_arp->ar_sha, target_iface->addr, ETHER_ADDR_LEN);
    reply_arp->ar_sip = target_iface->ip;
    memcpy(reply_arp->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_arp->ar_tip = arp_hdr->ar_sip;

    // Log and send reply
    printf("\n=== Sending ARP Reply Header ===\n");
    print_hdr_arp((uint8_t *)reply_arp);
    sr_send_packet(sr, reply, reply_len, interface);
    printf("ARP reply sent\n");

    free(reply);
}

/*---------------------------------------------------------------------
 * Method: process_arp_reply
 * Scope: Static
 *
 * Processes ARP replies by updating the ARP cache and forwarding any
 * queued packets for the resolved IP.
 *
 * Parameters:
 * - sr: Router instance
 * - packet: Raw Ethernet frame with ARP reply
 *---------------------------------------------------------------------*/
static void process_arp_reply(struct sr_instance *sr, uint8_t *packet) {
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    printf("Received ARP reply from %u.%u.%u.%u\n",
           (ntohl(arp_hdr->ar_sip) >> 24) & 0xFF,
           (ntohl(arp_hdr->ar_sip) >> 16) & 0xFF,
           (ntohl(arp_hdr->ar_sip) >> 8) & 0xFF,
           ntohl(arp_hdr->ar_sip) & 0xFF);

    // Insert into ARP cache and get any matching request
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (!req) {
        printf("No queued packets for this ARP reply\n");
        return;
    }

    printf("Found queued packets for this IP, forwarding them\n");
    struct sr_packet *pkt = req->packets;
    while (pkt) {
        struct sr_if *out_iface = sr_get_interface(sr, pkt->iface);
        if (!out_iface) {
            printf("Could not find outgoing interface %s for queued packet\n", pkt->iface);
            pkt = pkt->next;
            continue;
        }

        sr_ethernet_hdr_t *queued_eth_hdr = (sr_ethernet_hdr_t *)pkt->buf;
        memcpy(queued_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(queued_eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);

        printf("Forwarding queued packet through interface %s\n", pkt->iface);
        sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
        pkt = pkt->next;
    }

    sr_arpreq_destroy(&sr->cache, req);
}

/*---------------------------------------------------------------------
 * Method: handle_ip_packet
 * Scope: Static
 *
 * Processes IP packets, checking if they’re for the router or need
 * forwarding. Handles TTL expiration and checksum validation.
 *
 * Parameters:
 * - sr: Router instance
 * - packet: Raw Ethernet frame with IP packet
 * - len: Packet length
 * - iface: Receiving interface
 * - interface: Name of receiving interface
 *---------------------------------------------------------------------*/
static void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, const char *interface) {
    printf("Received IP packet\n");

    // Ensure packet includes IP header
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        printf("Packet too small for IP header (%u bytes, need %zu)\n", len,
               sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        return;
    }

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    printf("IP packet - Source: %u.%u.%u.%u, Dest: %u.%u.%u.%u\n",
           (ntohl(ip_hdr->ip_src) >> 24) & 0xFF,
           (ntohl(ip_hdr->ip_src) >> 16) & 0xFF,
           (ntohl(ip_hdr->ip_src) >> 8) & 0xFF,
           ntohl(ip_hdr->ip_src) & 0xFF,
           (ntohl(ip_hdr->ip_dst) >> 24) & 0xFF,
           (ntohl(ip_hdr->ip_dst) >> 16) & 0xFF,
           (ntohl(ip_hdr->ip_dst) >> 8) & 0xFF,
           ntohl(ip_hdr->ip_dst) & 0xFF);

    // Validate IP checksum
    uint16_t received_checksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if (received_checksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))) {
        printf("IP checksum mismatch (received %04x, calculated %04x), dropping packet\n",
               received_checksum, cksum(ip_hdr, sizeof(sr_ip_hdr_t)));
        return;
    }

    // Check if packet is for one of our interfaces
    struct sr_if *dest_iface = find_interface_by_ip(sr, ip_hdr->ip_dst);
    if (dest_iface) {
        process_ip_for_us(sr, packet, len, dest_iface, interface);
        return;
    }

    // Check TTL before forwarding
    if (ip_hdr->ip_ttl <= 1) {
        printf("TTL expired, sending ICMP time exceeded\n");
        send_icmp_reply(sr, packet, len, iface, interface, 11, 0); // Type 11, Code 0: TTL Exceeded
        return;
    }

    // Forward the packet
    forward_ip_packet(sr, packet, len, iface, interface);
}



static void process_ip_for_us(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface, const char *interface) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *in_iface = sr_get_interface(sr, interface); // Use receiving interface

    // Handle ICMP Echo Request
    if (len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
            printf("Sending ICMP echo reply\n");

            uint16_t ip_total_len = ntohs(ip_hdr->ip_len);
            uint16_t reply_packet_len = sizeof(sr_ethernet_hdr_t) + ip_total_len;
            uint16_t icmp_total_len = ip_total_len - sizeof(sr_ip_hdr_t);

            uint8_t *reply = malloc(reply_packet_len);
            if (!reply) {
                fprintf(stderr, "Memory allocation failed for ICMP echo reply\n");
                return;
            }

            sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply;
            sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
            sr_icmp_hdr_t *reply_icmp = (sr_icmp_hdr_t *)((uint8_t *)reply_ip + sizeof(sr_ip_hdr_t));

            memcpy(reply_icmp, icmp_hdr, icmp_total_len);
            memcpy(reply_eth->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN);
            memcpy(reply_eth->ether_shost, in_iface->addr, ETHER_ADDR_LEN); // Use receiving interface MAC
            reply_eth->ether_type = htons(ethertype_ip);

            reply_ip->ip_v = 4;
            reply_ip->ip_hl = sizeof(sr_ip_hdr_t) / 4;
            reply_ip->ip_tos = 0;
            reply_ip->ip_len = htons(ip_total_len);
            reply_ip->ip_id = ip_hdr->ip_id;
            reply_ip->ip_off = htons(IP_DF);
            reply_ip->ip_ttl = 64;
            reply_ip->ip_p = ip_protocol_icmp;
            reply_ip->ip_src = in_iface->ip; 
            reply_ip->ip_dst = ip_hdr->ip_src; 
            reply_ip->ip_sum = 0;
            reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));

            reply_icmp->icmp_type = 0;
            reply_icmp->icmp_code = 0;
            reply_icmp->icmp_sum = 0;
            reply_icmp->icmp_sum = cksum(reply_icmp, icmp_total_len);

            sr_send_packet(sr, reply, reply_packet_len, in_iface->name); 
            free(reply);
            return;
        }
    }

    // Handle TCP/UDP (Port Unreachable)
    if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17) {
        printf("TCP/UDP packet to router, sending ICMP port unreachable\n");
        send_icmp_reply(sr, packet, len, in_iface, interface, 3, 3); // Use receiving interface
    }
}


/*---------------------------------------------------------------------
 * Method: forward_ip_packet
 * Scope: Static
 *
 * Forwards an IP packet to its next hop, handling TTL decrement and ARP
 * resolution if necessary.
 *
 * Parameters:
 * - sr: Router instance
 * - packet: Raw Ethernet frame with IP packet
 * - len: Packet length
 * - in_iface: Receiving interface
 * - in_interface: Name of receiving interface
 *---------------------------------------------------------------------*/
static void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *in_iface, const char *in_interface) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    struct sr_rt *rt_entry = sr_lookup_rt(sr, ip_hdr->ip_dst);
    if (!rt_entry) {
        printf("No route found for destination IP %u.%u.%u.%u, sending ICMP network unreachable\n",
               (ntohl(ip_hdr->ip_dst) >> 24) & 0xFF,
               (ntohl(ip_hdr->ip_dst) >> 16) & 0xFF,
               (ntohl(ip_hdr->ip_dst) >> 8) & 0xFF,
               ntohl(ip_hdr->ip_dst) & 0xFF);
        send_icmp_reply(sr, packet, len, in_iface, in_interface, 3, 0); // Type 3, Code 0: Network Unreachable
        return;
    }

    printf("Found route to %u.%u.%u.%u via interface %s\n",
           (ntohl(ip_hdr->ip_dst) >> 24) & 0xFF,
           (ntohl(ip_hdr->ip_dst) >> 16) & 0xFF,
           (ntohl(ip_hdr->ip_dst) >> 8) & 0xFF,
           ntohl(ip_hdr->ip_dst) & 0xFF,
           rt_entry->interface);

    struct sr_if *out_iface = sr_get_interface(sr, rt_entry->interface);
    uint32_t next_hop_ip = (rt_entry->gw.s_addr == 0) ? ip_hdr->ip_dst : rt_entry->gw.s_addr;

    if (rt_entry->gw.s_addr == 0) {
        printf("Directly connected network, ARPing for destination: %u.%u.%u.%u\n",
               (ntohl(next_hop_ip) >> 24) & 0xFF,
               (ntohl(next_hop_ip) >> 16) & 0xFF,
               (ntohl(next_hop_ip) >> 8) & 0xFF,
               ntohl(next_hop_ip) & 0xFF);
    } else {
        printf("Using gateway: %u.%u.%u.%u\n",
               (ntohl(next_hop_ip) >> 24) & 0xFF,
               (ntohl(next_hop_ip) >> 16) & 0xFF,
               (ntohl(next_hop_ip) >> 8) & 0xFF,
               ntohl(next_hop_ip) & 0xFF);
    }

    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if (!arp_entry) {
        printf("No ARP entry found, queueing packet and sending ARP request\n");
        sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, rt_entry->interface);
        sr_arpcache_sweepreqs(sr);
    } else {
        printf("Found ARP entry, forwarding packet\n");
        memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        free(arp_entry);
        sr_send_packet(sr, packet, len, rt_entry->interface);
        printf("Packet forwarded through interface %s\n", rt_entry->interface);
    }
}

/*---------------------------------------------------------------------
 * Method: send_icmp_reply
 * Scope: Static
 *
 * Constructs and sends an ICMP reply (e.g., Time Exceeded, Unreachable).
 *
 * Parameters:
 * - sr: Router instance
 * - packet: Original packet triggering the ICMP response
 * - len: Original packet length
 * - iface: Interface to send from
 * - interface: Name of the sending interface
 * - type: ICMP type (e.g., 3 for Unreachable, 11 for Time Exceeded)
 * - code: ICMP code (specific to type)
 *---------------------------------------------------------------------*/
static void send_icmp_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                            struct sr_if *iface, const char *interface,
                            uint8_t type, uint8_t code) {
    size_t reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *reply = malloc(reply_len);
    if (!reply) {
        fprintf(stderr, "Memory allocation failed for ICMP reply\n");
        return;
    }

    sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply;
    sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *reply_icmp = (sr_icmp_t3_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    sr_ethernet_hdr_t *orig_eth = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *orig_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    // Use correct outgoing interface
    struct sr_if *out_iface = sr_get_interface(sr, interface);
    if (!out_iface) {
        fprintf(stderr, "Failed to get interface %s for ICMP reply\n", interface);
        free(reply);
        return;
    }

    // Ethernet header
    memcpy(reply_eth->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
    reply_eth->ether_type = htons(ethertype_ip);

    // IP header
    reply_ip->ip_v = 4;
    reply_ip->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    reply_ip->ip_tos = 0;
    reply_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    reply_ip->ip_id = htons(0);
    reply_ip->ip_off = htons(IP_DF);
    reply_ip->ip_ttl = 64;
    reply_ip->ip_p = ip_protocol_icmp;
    reply_ip->ip_src = out_iface->ip;
    reply_ip->ip_dst = orig_ip->ip_src;
    reply_ip->ip_sum = 0;
    reply_ip->ip_sum = cksum(reply_ip, sizeof(sr_ip_hdr_t));

    // ICMP header
    reply_icmp->icmp_type = type;
    reply_icmp->icmp_code = code;
    reply_icmp->unused = 0;
    reply_icmp->next_mtu = 0;
    memcpy(reply_icmp->data, orig_ip, ICMP_DATA_SIZE);
    reply_icmp->icmp_sum = 0;
    reply_icmp->icmp_sum = cksum(reply_icmp, sizeof(sr_icmp_t3_hdr_t));

    sr_send_packet(sr, reply, reply_len, interface);
    free(reply);
}





/*---------------------------------------------------------------------
 * Method: find_interface_by_ip
 * Scope: Static
 *
 * Searches the router’s interface list for one matching a given IP.
 *
 * Parameters:
 * - sr: Router instance
 * - ip: IP address to match (in network byte order)
 *
 * Returns:
 * - Pointer to matching interface, or NULL if not found
 *---------------------------------------------------------------------*/
static struct sr_if *find_interface_by_ip(struct sr_instance *sr, uint32_t ip) {
    struct sr_if *intf = sr->if_list;
    while (intf) {
        if (intf->ip == ip) {
            return intf;
        }
        intf = intf->next;
    }
    return NULL;
}