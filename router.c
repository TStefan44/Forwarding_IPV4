#include "queue.h"
#include "skel.h"
#include "list.h"

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arp_table_len;

/**
 * Compare function used for sorting the rtable
 */
int cmp(const void* a1, const void *a2) {
	//convert a1 and a2 to table entry struct
	struct route_table_entry *r1 = (struct route_table_entry *)a1;
	struct route_table_entry *r2 = (struct route_table_entry *)a2;

	//compare 2 entries ascending on mask, then on prefix if masks are equal
	if (ntohl(r1->mask) != ntohl(r2->mask)) {
		return ntohl(r1->mask) - ntohl(r2->mask);
	} else {
		return ntohl(r1->prefix) - ntohl(r2->prefix);
	}
}

/**
 * Function used to send arp
 * Taken form last year skel;
 */
void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op)
{
	// create new packet and arp header
	packet m;
	struct arp_header arp_hdr;

	// fill data in arp header as shown in assignement
	arp_hdr.htype = htons(ARPHRD_ETHER); // Ethernet
	arp_hdr.ptype = htons(2048); // IPv4
	arp_hdr.op = arp_op; // Request or Reply
	arp_hdr.hlen = ARPHRD_IEEE802; // 6 for MAC
	arp_hdr.plen = ARPHRD_PRONET; // 4 fo IP

	// set sender hardware addr and target hardware addr
	// with data from ethernet header
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, 6);

	// set sender and target IP addr
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;

	// add ethernet header in payload
	memcpy(m.payload, eth_hdr, sizeof(struct ethhdr));
	// add arp header in payload after ethernet header
	memcpy(m.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));

	// set interface and length of packet
	m.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	m.interface = interface;

	// send packet
	send_packet(&m);
}

/**
 * Liniar search for arp entries in cache by destination ip
 */
struct arp_entry* search_cache(uint32_t dest_ip) {
	
	if (arp_table_len == 0) {
		// empty arp cache case
		return NULL;
	} else {
		for (int i = 0; i < arp_table_len; i++) {
			if(ntohl(dest_ip) == ntohl(arp_table[i].ip))
			return &arp_table[i];
		}
		// no match found
		return NULL;
	}
}

/**
 * Function for building an ethernet header.
 * Taken from last year skel
 */
void build_ethhdr(struct ether_header *eth_hdr, uint8_t *sha, uint8_t *dha, unsigned short type)
{
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;
}

/**
 * Function for sending icmp. Used for echo request and echo reply
 * Taken from last year skel
 */
void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq,
				struct iphdr *old_hdr)
{
	struct ether_header eth_hdr; // ethernet header
	struct iphdr ip_hdr; // IPv4 header
	struct icmphdr icmp_hdr = { // ICMP header
		.type = type,
		.code = code,
		.checksum = 0,
		.un.echo = {
			.id = id,
			.sequence = seq,
		}
	};
	packet packet; // packet to be send
	void *payload; // payload of packet to be send

	// Initialise ethernet header with MAC addresses
	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	
	// Fill ip header data
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum((uint8_t *)(&ip_hdr), sizeof(struct iphdr));
	
	// set icmp checksum
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	// add ethernet header in payload
	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	
	// add IPv4 header in payload after ethernet header
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	
	// add ICMP header in payload after IPV4 header
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));

	// add old IPv4 in payload after ICMP
	payload += sizeof(struct icmphdr);
	memcpy(payload, old_hdr, sizeof(struct icmphdr));

	// set len and interface of packet
	packet.len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr);
	packet.interface = interface;

	// send packet
	send_packet(&packet);
}

/**
 * Function for sending icmp. Used for echo time exceeded and no destination
 * reached. Add after ICMP header the last 64 Bytes form old IPv4.
 * Taken from last year skel.
 */
void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface,
					struct iphdr *old_hdr)
{

	struct ether_header eth_hdr; // ethernet header
	struct iphdr ip_hdr; // IPv4 header
	struct icmphdr icmp_hdr = { // ICMP header
		.type = type,
		.code = code,
		.checksum = 0,
	};
	packet packet; // packet to be send
	void *payload; // payload of packet to be send

	// Initialise ethernet header with MAC addresses
	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	
	// Fill ip header data
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 255;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum((uint8_t *)(&ip_hdr), sizeof(struct iphdr));
	
	// set icmp checksum
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	// add ethernet header in payload
	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));

	// add IPv4 header in payload after ethernet header
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));

	// add ICMP header in payload after IPV4 header
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));

	// add 64 Bytes from old IPv4 in payload after ICMP
	payload += sizeof(struct icmphdr);
	memcpy(payload, old_hdr, 64);


	// set len and interface of packet
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
	packet.interface = interface;

	// send packet
	send_packet(&packet);
}

/**
 * Binary search for best route in route table.
 * Return longest prefix match. If no match return NULL
 * dest_ip is already send with ntohl
 */
struct route_table_entry *get_best_route_binary(uint32_t dest_ip) {
    size_t idx = -1;
    int i = 0;
    int j = rtable_len - 1;
    int m;

    while (i <= j) {
		m = (i + j) / 2;
		uint32_t mask_m = ntohl(rtable[m].mask);
		uint32_t prefix_m = ntohl(rtable[m].prefix);

        if (((dest_ip & mask_m) == prefix_m)) {
			// first match found
            if (idx == -1) idx = m;
            else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) idx = i;
			// look further in table for a better match
            i = m + 1;
        } else if (((dest_ip & mask_m) < prefix_m)) {
            j = m - 1;
        } else {
            i = m + 1;
        }
    }

    if (idx == -1)
		// no mtach found
        return NULL;
    else
		// match found
        return &rtable[idx];    
}   

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t dest_ip) {
    size_t idx = -1;	

    for (size_t i = 0; i < rtable_len; i++) {
        if (((dest_ip & ntohl(rtable[i].mask)) == ntohl(rtable[i].prefix))) {
			if (idx == -1) idx = i;
			else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) idx = i;
		}
    }
    
    if (idx == -1)
        return NULL;

    else
        return &rtable[idx];
}

/**
 * Return host ip addr from interface
 */
uint32_t get_my_ip(packet m) {
	char *ip_object = get_interface_ip(m.interface);
	struct in_addr adr_ip;
	inet_aton(ip_object, &adr_ip);
	return adr_ip.s_addr;
}

/**
* Returns a pointer (eg. &nei_table[i]) to the best matching neighbor table entry.
* for the given protocol and destination address. Or NULL if there is no matching route.
* Taken from lab
*/
struct arp_entry *get_nei_entry(uint32_t dest_ip) {
    for (size_t i = 0; i < arp_table_len; i++) {
        if ((memcmp(&dest_ip, &arp_table[i].ip, sizeof(__u32)) == 0))
            return &arp_table[i];
    }

    return NULL;
}

int main(int argc, char *argv[])
{
	queue arp_queue = queue_create();
    packet m;
    int rc;

    // populate route table and parses static arp map
    rtable = malloc(sizeof(struct route_table_entry) * 1000000);
    DIE(rtable == NULL, "memory");

    arp_table = malloc(sizeof(struct  arp_entry) * 100);
    DIE(arp_table == NULL, "memory");

	// set route and arp tables size
    rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len ,sizeof(struct route_table_entry), cmp);

    // Do not modify this line
    init(argc - 2, argv + 2);

    while (1) {
        rc = get_packet(&m);
        DIE(rc < 0, "get_packet");
        
		// extract ethernet header from payload
        struct ether_header *eth = (struct ether_header *) m.payload;

        // L2 verification
        // get MAC interface address
        uint8_t interface_mac[ETH_ALEN];
        get_interface_mac(m.interface, interface_mac);
            
        // get destination MAC address from ethernet header
		uint8_t ether_dest[ETH_ALEN];
		memcpy(ether_dest, eth->ether_dhost, ETH_ALEN);

		// generate broadcast MAC address
        uint8_t broadcast_addr[ETH_ALEN];
        hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast_addr);

		if (memcmp(interface_mac, ether_dest, 6) != 0 &&
			memcmp(broadcast_addr, ether_dest, 6) != 0) {
				// Packet is not for this router or packet is not for broadcast
				continue;
			}

        // found IPv4 protocol. Extract IPv4 header
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {

            struct iphdr *iph = ((void *) eth) + sizeof(struct ether_header);
            // found ICMP protocol. Extract ICMP header
            if (iph->protocol == IPPROTO_ICMP) {
                struct icmphdr *icmph = ((void *) eth) + sizeof(struct ether_header) + sizeof(struct iphdr);

                //verify icmp checksum
                uint16_t cheacksum_icmp = ntohs(icmph->checksum);
                icmph->checksum = 0;
                if (ntohs(icmp_checksum((uint16_t *)icmph, sizeof(struct icmphdr))) != cheacksum_icmp) {
					// wrong ckecksum
					continue;
                }

                //Packet is for this router and echo request detected
				uint32_t my_ip = get_my_ip(m);
                if (ntohl(my_ip) == ntohl(iph->daddr) && icmph->type == ICMP_ECHO && icmph->code == 0) {
					// send back echo reply
                    send_icmp(iph->saddr, iph->daddr, 
						eth->ether_dhost, eth->ether_shost, ICMP_ECHOREPLY, 0,
						m.interface, icmph->un.echo.id, icmph->un.echo.sequence, iph);
                    continue;
                }
            }

            //check ip checksum
            uint16_t checksum_ip = ntohs(iph->check);
            iph->check = 0;
            if (ntohs(ip_checksum((uint8_t *) iph, sizeof(struct iphdr))) != checksum_ip) {
				// wrong checksum
                continue;
            }

            //decrement ttl
            iph->ttl--;
            if (iph->ttl <= 0) {
                // Time exceeded. Send ICMP
                send_icmp_error(iph->saddr, iph->daddr, 
						eth->ether_dhost, eth->ether_shost, ICMP_TIME_EXCEEDED, 0,
						m.interface, iph);
                continue;
            }

            uint32_t dest_ip = iph->daddr;
            struct route_table_entry *route = get_best_route_binary(ntohl(dest_ip));
            if (route == NULL) {
                //Destination unreachable. Send error ICMP
                send_icmp_error(iph->saddr, get_my_ip(m), interface_mac,
						eth->ether_shost, ICMP_DEST_UNREACH, 0,
						m.interface, iph);
                continue;
            }

			// search for dest MAC address
			struct arp_entry *nei = search_cache(route->next_hop);
			if (nei == NULL) {
				// no match in arp cache
				// change what is posible and put packet in queue
				get_interface_mac(route->interface, eth->ether_shost);
            	m.interface = route->interface;
				iph->check = 0;
            	iph->check = ip_checksum((uint8_t*) iph, sizeof(struct iphdr));

				// put packet in queue
				packet *m_arp = malloc(1 * sizeof(packet));
				memcpy(m_arp, &m, sizeof(packet));
				queue_enq(arp_queue, (void*)m_arp);

				// make ethernet header for arp
				struct ether_header *arp_eth = malloc(1 * sizeof(struct ether_header));
				arp_eth->ether_type = htons(ETH_P_ARP);
				// ethernet shost = interface MAC address
				get_interface_mac(route->interface, arp_eth->ether_shost);
				// ethernet dhost = broadcast MAC address
				memcpy(arp_eth->ether_dhost, broadcast_addr, ETH_ALEN);

				// send arp
				send_arp(route->next_hop, get_my_ip(m), arp_eth, m.interface, htons(ARPOP_REQUEST));
				continue;
			}
			
			// recalculate IPv4 checksum
            iph->check = 0;
            iph->check = ip_checksum((uint8_t*) iph, sizeof(struct iphdr));

			// modify MAC addresses in ethernet header
            memcpy(eth->ether_dhost, nei->mac, ETH_ALEN);
            get_interface_mac(route->interface, eth->ether_shost);
            
			// update interface
			m.interface = route->interface;

			// send packet
            send_packet(&m);

		// found ARP protocol. Extract arp header
        } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {

			struct arp_header *arph = ((void *) eth) + sizeof(struct ether_header);

			// arp request receive. Send back host MAC address
			if (ntohs(arph->op) == ARPOP_REQUEST) {
				// match host IP for arp request
				if (ntohl(arph->tpa) == ntohl(get_my_ip(m))) {
					// make ethernet header for arp
					struct ether_header *arp_eth = malloc(1 * sizeof(struct ether_header));
					arp_eth->ether_type = htons(ETH_P_ARP);
					// ethernet sources host = MAC address of interface host
					get_interface_mac(m.interface, arp_eth->ether_shost);
					// ethernest destination host = dhost MAC address of received packet
					memcpy(arp_eth->ether_dhost, arph->sha, ETH_ALEN);
					// send arp reply with made ethernet header
					send_arp(arph->spa, arph->tpa, arp_eth, m.interface, htons(ARPOP_REPLY));
				}
			// arp reply received
			} else if (ntohs(arph->op) == ARPOP_REPLY) {
				// extract ip address for next hope and mac addres from queue
				// put them in a arp entry
				struct arp_entry *new_arp = malloc(1 * sizeof(sizeof (struct arp_entry)));
				new_arp->ip = arph->spa;
				memcpy(new_arp->mac, arph->sha, ETH_ALEN);

				// cons new arp entry in list
				arp_table[arp_table_len].ip = new_arp->ip;
				memcpy(arp_table[arp_table_len].mac, new_arp->mac, ETH_ALEN);
				arp_table_len++;

				// extract packets waiting to be send
				while (!queue_empty(arp_queue)) {
					// extract current packet from queue
					packet *queue_m = (packet*) queue_deq(arp_queue);
					// ethernet header
					struct ether_header *eth = (struct ether_header *) queue_m->payload;
					// IPv4 header
					struct iphdr *iph = (void *)eth + sizeof(struct ether_header);

					// => known MAC dest => can send packet
					memcpy(eth->ether_dhost, new_arp->mac, ETH_ALEN);

					// send current packet;
					send_packet(queue_m);
				}
			}
		}
    }
}