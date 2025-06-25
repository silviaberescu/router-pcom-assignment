#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <arpa/inet.h>
#define IP_ETHERTYPE 0x0800
#define ARP_ETHERTYPE 0x0806
#define ICMP_ECHO_REPLY 0        
#define ICMP_DEST_UNREACH 3      
#define ICMP_TIME_EXCEEDED 11    
#define ICMP_ECHO_REQUEST 8
#define ARP_REQUEST 1
#define ARP_REPLY 2


void create_icmp_error_packet(struct ether_hdr *eth_hdr_old, struct ip_hdr *ip_hdr_old, uint8_t type, uint8_t code, size_t interface) {

    char* packet = malloc(MAX_PACKET_LEN);

    struct ether_hdr *eth_hdr = (struct ether_hdr *)packet;

    memcpy(eth_hdr->ethr_dhost, eth_hdr_old->ethr_shost, 6);
    get_interface_mac(interface, eth_hdr->ethr_shost);
    eth_hdr->ethr_type = htons(IP_ETHERTYPE);

    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(packet + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    icmp_hdr->check = 0;
    icmp_hdr->mcode = code;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
    ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
    ip_hdr->ver = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->id = htons(1);
    ip_hdr->frag = 0;
    ip_hdr->ttl = 64;
    ip_hdr->proto = IPPROTO_ICMP;
    ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
    ip_hdr->dest_addr = ip_hdr_old->source_addr;
    ip_hdr->checksum = 0;
    icmp_hdr->check = 0;
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

    
    memcpy((char *)icmp_hdr + sizeof(struct icmp_hdr), ip_hdr_old, sizeof(struct ip_hdr) + 8);
    icmp_hdr->mtype = type;
    size_t icmp_len = sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
    icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_len));

    send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len, packet, interface);
    free(packet);
}



// struct route_table_entry *get_best_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_size) {
// 	for (int i = 0; i < rtable_size; i++) {
// 		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
// 			return &rtable[i];
// 		}
// 	} 
// 	return NULL;
// }


struct arp_table_entry *get_arp_entry(uint32_t ip, struct arp_table_entry *arp_table, int arp_table_size) {
    for (int i = 0; i < arp_table_size; i++) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}
struct route_table_entry *binary_search_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len) {
    struct route_table_entry *next_hop = NULL;
    uint32_t dest = ntohl(ip_dest);
    int r = rtable_len - 1;
    int l = 0;
    while (l <= r) {
        int m = l + (r - l) / 2;
        uint32_t current_prefix = ntohl(rtable[m].prefix);
        uint32_t current_mask = ntohl(rtable[m].mask);

        if ((ip_dest & rtable[m].mask) == rtable[m].prefix && !next_hop) {
            next_hop = &rtable[m];
        }

        if ((ip_dest & rtable[m].mask) == rtable[m].prefix && next_hop) {
            if (current_mask > ntohl(next_hop->mask)) {
                next_hop = &rtable[m];
                
            }
        }

        if (current_prefix <= dest) {
            l = m + 1;
        } else {
            r = m - 1;
        }
    }

    return next_hop;
}

static inline int32_t dr_comparator(const void *a, const void *b)
{
    struct route_table_entry route1 = *(struct route_table_entry *)a;
    struct route_table_entry route2 = *(struct route_table_entry *)b;

    if (ntohl(route1.prefix) < ntohl(route2.prefix)) {
        return -1;
	} else if (ntohl(route1.prefix) > ntohl(route2.prefix)){
		return 1;
	} else {
        if (ntohl(route1.mask) > ntohl(route2.mask)) {
            return 1;
		} else {
			return -1;
		}
    }
    return -1;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);


    struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
    int rtable_size = read_rtable(argv[1], rtable);
	
    //aici sortat tabelul
	qsort(rtable, rtable_size, sizeof(rtable[0]), dr_comparator);

    // pentru tabela statica
    // struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * 20);
    // int arp_table_size = parse_arp_table("arp_table.txt", arp_table);
  
	struct arp_table_entry* cache = calloc(15, sizeof(struct arp_table_entry));
    queue q = create_queue(); //coada de pachete care asteapta adresa mac

    struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	int arp_len = 0;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


       
        if (ntohs(eth_hdr->ethr_type) == IP_ETHERTYPE) { //e de tip ip
			if (inet_addr(get_interface_ip(interface)) == ip_hdr->dest_addr) { //e pt router
                //se trimite echo reply
                struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
                if(icmp_hdr->mtype == ICMP_ECHO_REQUEST) {
                    get_interface_mac(interface, eth_hdr->ethr_shost);
                    uint8_t tmp_mac[6];
                    memcpy(tmp_mac, eth_hdr->ethr_shost, 6);
                    memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
                    memcpy(eth_hdr->ethr_dhost, tmp_mac, 6);

                    icmp_hdr->check = 0;
                    icmp_hdr->mtype = ICMP_ECHO_REPLY;
                    uint32_t icmp_len = ntohs(ip_hdr->tot_len) - sizeof(struct ip_hdr) - sizeof(struct icmp_hdr);
                    icmp_hdr->mcode = 0;
                    icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr)));
        
                    int8_t *icmp_body = malloc(icmp_len);
                   
                    memcpy(icmp_body, (char *)icmp_hdr + sizeof(struct icmp_hdr), icmp_len);


                    uint32_t tmp_ip = ip_hdr->source_addr;
                    ip_hdr->ttl = htons(64);
                    ip_hdr->proto = IPPROTO_ICMP;
                    ip_hdr->source_addr = ip_hdr->dest_addr;
                    ip_hdr->dest_addr = tmp_ip;
                    ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + icmp_len);
                    ip_hdr->checksum = 0;
                    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
                    
                    memcpy((char *)icmp_hdr + sizeof(struct icmp_hdr), icmp_body, icmp_len);
                    
                    send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + icmp_len, (char *)eth_hdr, interface);
                    free(icmp_body);
                }


            } else { //nu e pt router
            
                //verificare checksum
                uint16_t received_checksum = ip_hdr->checksum;
                ip_hdr->checksum = 0;
               
                if (htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) != received_checksum) {
                    continue;
                }

                //verificare ttl si actualizare
                if(ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
                    //trimitere icmp time exceeded
					create_icmp_error_packet(eth_hdr, ip_hdr, ICMP_TIME_EXCEEDED, 0, interface);
                    continue;
                }
                ip_hdr->ttl--;

                //cautare next hop in tabela de rutare
                struct route_table_entry *next_route = binary_search_route(ip_hdr->dest_addr, rtable, rtable_size);
				
				
                if (next_route == NULL) {
                    //trimitere icmp dest unreachable
					create_icmp_error_packet(eth_hdr, ip_hdr, ICMP_DEST_UNREACH, 0, interface);
                    continue;
                }

                //actualizare checksum
                ip_hdr->checksum = 0;
                ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

                // pentru static
                // struct arp_table_entry *next_hop_mac = get_arp_entry(next_route->next_hop, arp_table, arp_table_size);
                // se cauta in cache adresa mac pentru adresa ip a urmatorului hop
				struct arp_table_entry *next_hop_mac = get_arp_entry(next_route->next_hop, cache, arp_len);
                if (!next_hop_mac) { //nu s a gasit in cache
                    // bagam pachetul in coada
                    // se trimite arp request se genereze un pachet cu un antet Ethernet, urmat de un antet ARP
                    char *copy = (char * ) malloc(MAX_PACKET_LEN);
					memcpy(copy, buf, MAX_PACKET_LEN);
					queue_enq(q, copy);

                    //trimitere arp request

					char *new_buf = malloc(MAX_PACKET_LEN);
					

					struct ether_hdr *new_eth_hdr = (struct ether_hdr *) new_buf;
					struct arp_hdr *new_arp_hdr = (struct arp_hdr *) (new_eth_hdr + sizeof(struct ether_hdr));
					uint8_t *mac_dest = malloc(6);
					memset(mac_dest, 0xFF, 6);
					memcpy(new_eth_hdr->ethr_dhost, mac_dest, 6);

					get_interface_mac(next_route->interface, new_eth_hdr->ethr_shost);

					new_eth_hdr->ethr_type = htons(ARP_ETHERTYPE);

					new_arp_hdr->hw_type = htons(1);
					new_arp_hdr->proto_type  = htons(IP_ETHERTYPE);
					new_arp_hdr->hw_len = 6;
					new_arp_hdr->proto_len = 4;
					new_arp_hdr->opcode = htons(ARP_REQUEST);


					
					get_interface_mac(next_route->interface, new_arp_hdr->shwa);
					
					new_arp_hdr->sprotoa = inet_addr(get_interface_ip(next_route->interface));

					memset(new_arp_hdr->thwa, 0, 6);

					new_arp_hdr->tprotoa = next_route->next_hop;
					memcpy(new_buf, new_eth_hdr, sizeof(struct ether_hdr));
					memcpy(new_buf + sizeof(struct ether_hdr), new_arp_hdr, sizeof(struct arp_hdr));
					send_to_link(sizeof(struct arp_hdr) + sizeof(struct ether_hdr), new_buf, next_route->interface);
                    
                    continue;
                }
				
                memcpy(eth_hdr->ethr_dhost, next_hop_mac->mac, 6);
                get_interface_mac(next_route->interface, eth_hdr->ethr_shost);
                //trimitere pachet pe interfata corespunzatoare
				send_to_link(len, buf, next_route->interface);
			}

		// e de tip arp reply
        // se adauga in cache
        // parcurge lista de pachete care asteapta raspunsuri ARP si le va trimite pe cele pentru care adresa urmatorului hop este cunoscuta

        } else if (ntohs(eth_hdr->ethr_type) == ARP_ETHERTYPE) { // ARP packet
            struct arp_hdr * arp_hdr = (struct arp_hdr * )(buf + sizeof(struct ether_hdr));
         
            if (ntohs(arp_hdr->opcode) == ARP_REQUEST) {
				arp_hdr -> opcode = htons(ARP_REPLY);

				memcpy(arp_hdr -> thwa, arp_hdr->shwa, 6);

				uint8_t *interface_mac = malloc(6);
                get_interface_mac(interface, interface_mac);
				memcpy(arp_hdr -> shwa, interface_mac, 6);
				 
				arp_hdr -> tprotoa = arp_hdr->sprotoa;
				arp_hdr -> sprotoa = inet_addr(get_interface_ip(interface));

                memcpy(eth_hdr->ethr_dhost, arp_hdr ->thwa, 6);
				get_interface_mac(interface, eth_hdr->ethr_shost);
                
                send_to_link(len, buf, interface);
                free(interface_mac);
            }

            if (ntohs(arp_hdr ->opcode) == ARP_REPLY) {

                if (get_arp_entry(arp_hdr->sprotoa, cache, arp_len) == NULL) {

                    cache[arp_len].ip = arp_hdr ->sprotoa;
                    memcpy(cache[arp_len].mac, arp_hdr ->shwa, 6);
                    arp_len++;
                
					queue newQueue = create_queue();
					while (!queue_empty(q)) {
						
						char *packet = queue_deq(q);
						struct ether_hdr *eth_hdr_1 = (struct ether_hdr *) packet;

						struct arp_table_entry *new_arp_entry = get_arp_entry(arp_hdr->sprotoa, cache, arp_len);
						if (new_arp_entry == NULL) {
							queue_enq(newQueue, packet);
							continue;
						}

						u_int8_t *interface_mac = malloc(6);
						get_interface_mac(interface, interface_mac);

						memcpy(eth_hdr_1->ethr_shost, interface_mac, 6);
						memcpy(eth_hdr_1->ethr_dhost, new_arp_entry -> mac, 6);
						send_to_link(sizeof(struct arp_hdr) + sizeof(struct ether_hdr), packet, interface);
                        free(interface_mac);
					}
					free(q);
					q = newQueue;
				}
            }
        }
	}
}

