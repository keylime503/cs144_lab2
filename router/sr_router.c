/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

struct sr_rt * lookupRoutingTbl(struct sr_instance* sr, uint32_t ip_dest)
{
	struct sr_rt * rtIter = sr->routing_table;
	while(rtIter)
	{
		/* TODO: Fix longest prefix match */
		if(rtIter->dest.s_addr == ip_dest)
		{
			return rtIter;
		}
		rtIter = rtIter->next;
	}
	return NULL;
}


/* Send echo reply ICMP message (for ping) */
void send_echo_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len)
{
	/* Get length of ICMP header + data for cksum calculation */
	int cksum_length = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);

	/* Get pointers to ICMP and IP headers */
	sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));	
	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;

	/* Modify ICMP header */
	icmp_hdr->icmp_type = 0;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum((void *) icmp_hdr, cksum_length);

	/* Modify IP header */
	uint32_t temp_ip = ip_hdr->ip_src;
	ip_hdr->ip_src = ip_hdr->ip_dst;
	ip_hdr->ip_dst = temp_ip;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum((void *) ip_hdr, sizeof(sr_ip_hdr_t));

	/* Lookup ip_dst in routing table */
	struct sr_rt * rtIter = lookupRoutingTbl(sr, ip_hdr->ip_dst);
	if (rtIter)
	{
		/* Lookup gateway IP in ARP table */
		uint32_t gwIP = rtIter->gw.s_addr;

		struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), gwIP);
		if (entry)
		{
			/* Send to Layer 2 */
			send_layer_2(sr, packet, len, rtIter->interface, entry->mac, ethertype_ip);
       		free (entry);	
       		return;
		}
 		else
       	{
       		memcpy(eth_hdr->ether_shost, sr_get_interface(sr, rtIter->interface)->addr, ETHER_ADDR_LEN);
       		struct sr_arpreq * req = sr_arpcache_queuereq( &(sr->cache), gwIP, packet, len, rtIter->interface);
       		handle_arpreq(sr, req);
			return;
       	}
	}
	else
	{
		/* Drop packet */
		return;
	}

	return;
}

/* Method to send ICMP packet (fills IP header, sends to send_layer_2) to an interface. */
void send_icmp_packet(struct sr_instance* sr, uint32_t ip_dst, uint8_t icmp_type, uint8_t icmp_code, uint8_t * type_3_data)
{
	unsigned int len;
	uint8_t * packet;

	/* Create packet to hold ethernet header, ip header, and icmp type 3 header */
	len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	packet = (uint8_t *) malloc((size_t) len);

	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t3_hdr_t * icmp_3_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	/* Fill out ICMP header */
	icmp_3_hdr->icmp_type = icmp_type;
	icmp_3_hdr->icmp_code = icmp_code;
	icmp_3_hdr->unused = 0;
	icmp_3_hdr->next_mtu = 0;
	memcpy(icmp_3_hdr->data, type_3_data, ICMP_DATA_SIZE);
	icmp_3_hdr->icmp_sum = 0;
	icmp_3_hdr->icmp_sum = cksum((void *) icmp_3_hdr, sizeof(sr_icmp_t3_hdr_t));

	/* Fill out IP header */
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(len - 14);
	ip_hdr->ip_id = 0; /* Fix Maybe */
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 64; 
	ip_hdr->ip_p = ip_protocol_icmp;
	/*ip_hdr->ip_src = ip_src;*/
	ip_hdr->ip_dst = ip_dst;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum((void *) ip_hdr, sizeof(sr_ip_hdr_t));

	/* Lookup ip_dst in routing table */
	struct sr_rt * rtIter = lookupRoutingTbl(sr, ip_hdr->ip_dst);
	if (rtIter)
	{
		/* Assign IP header's ip_src */
		ip_hdr->ip_src = sr_get_interface(sr, rtIter->interface)->ip;

		/* Lookup gateway IP in ARP table */
		uint32_t gwIP = rtIter->gw.s_addr;

		struct sr_arpentry * entry = sr_arpcache_lookup( &(sr->cache), gwIP);
		if (entry)
		{
			/* Send to Layer 2 */
			send_layer_2(sr, packet, len, rtIter->interface, entry->mac, ethertype_ip);
       		free (entry);	
       		return;
		}
 		else
       	{
       		memcpy(eth_hdr->ether_shost, sr_get_interface(sr, rtIter->interface)->addr, ETHER_ADDR_LEN);
       		struct sr_arpreq * req = sr_arpcache_queuereq( &(sr->cache), gwIP, packet, len, rtIter->interface);
       		handle_arpreq(sr, req);
			return;
       	}
	}
	else
	{
		/* Drop packet */
		return;
	}
	return;
}

/* Method to send ARP packet (fills ARP header, sends to send_later_2) to an interface. */
void send_arp_packet(struct sr_instance* sr, char* interface/* lent */, void * ether_dest, uint32_t ip_dst, unsigned short ar_op)
{	
	/* Create packet to hold ethernet header and arp header */
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t * packet = (uint8_t *) malloc ((size_t) len);

	sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	/* Get sr_if for srcMAC address */
	struct sr_if * outgoingIFace = sr_get_interface(sr, interface);

	/* Fill out ARP header */
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(2048);
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ar_op);
	arp_hdr->ar_sip = outgoingIFace->ip;
	arp_hdr->ar_tip = ip_dst;
	memcpy(arp_hdr->ar_sha, outgoingIFace->addr, ETHER_ADDR_LEN);
	memcpy(arp_hdr->ar_tha, ether_dest, ETHER_ADDR_LEN);

	/* Send packet with space for ethernet to send_layer_2() to actually send packet */
	send_layer_2(sr, packet, len, interface, ether_dest, ethertype_arp);

	return;
}

/* Method to send packets (with space for ethernet header) to an interface. */
void send_layer_2(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, 
					char* interface/* lent */, void * destMAC, uint16_t type)
{
	/* Get sr_if for srcMAC address */
	struct sr_if * outgoingIFace = sr_get_interface(sr, interface);
	
	/* Modify Ethernet header */
	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
	memcpy(eth_hdr->ether_dhost, destMAC, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, outgoingIFace->addr, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(type);

	/* DEBUG: Print reply packet */
	printf("*** -> Printing outgoing packet\n");
	print_hdrs(packet, (uint32_t) len);

	/* Send a reply packet */
	sr_send_packet(sr, packet, len, interface);
	return;
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);
	printf("*** -> From interface %s \n", interface);
	print_hdrs(packet, (uint32_t) len);

	/*---------------------------------------------------------------------
	 * Layer 2
	 *---------------------------------------------------------------------*/

	/* Check that the packet is long enough for an ethernet header */
	unsigned int minlength = sizeof(sr_ethernet_hdr_t);
	if (len < minlength) {
    	printf("Failed to extract ETHERNET header, insufficient length\n");
    	return;
	}

	/* Extract ethernet header */
	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
	
	/* Get recieving interface */
	struct sr_if * recievingInterface = sr_get_interface(sr, interface);

	/* bcast array is FF:FF:FF:FF:FF:FF */
	uint8_t bcast[8] = { 255, 255, 255, 255, 255, 255 };
	
	/* Check if frame is destined to us or a broadcast frame
	   If not, drop packet
	 */
	if(memcmp( (void *) eth_hdr->ether_dhost, (void *) recievingInterface->addr, ETHER_ADDR_LEN) != 0 &&
	   memcmp( (void *) eth_hdr->ether_dhost, (void *) bcast, ETHER_ADDR_LEN) != 0)
	{
		/* Drop the packet */
		printf("Dest MAC Address does not match interface \n");
		printf("MAC Address Interface:");
		print_addr_eth( (uint8_t *) recievingInterface->addr);
		return;
	}

	/*---------------------------------------------------------------------
	 * Layer 3
	 *---------------------------------------------------------------------*/	
	
	/* Find type of Layer 3 packet */
	uint16_t ethtype = ethertype(packet);

	/* IP packet*/
	if (ethtype == ethertype_ip) 
	{ 
		/* Check that the packet is long enough for an IP header */
		minlength += sizeof(sr_ip_hdr_t);
		if (len < minlength) 
		{
			printf("Failed to extract IP header, insufficient length\n");
			return;
		}

		/* Extract the IP header */
		sr_ip_hdr_t * iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
		
		/* Save checksum */
		uint16_t ipCksum = iphdr->ip_sum;
		iphdr->ip_sum = 0;
		uint16_t computedCksum = cksum((void *) iphdr, sizeof(sr_ip_hdr_t));
		if(computedCksum != ipCksum)
		{
			printf("IP Header has wrong checksum.\n");
			printf("Computed: %d\n", computedCksum);
			return;
		}

		/* Decrement TTL */
		iphdr->ip_ttl--;

		/* If TTL is 0, drop packet and send ICMP Time Exceded */
		if(iphdr->ip_ttl == 0)
		{
			/* Send ICMP Message */
			printf("Sending ICMP Time Exceeded.\n");
			send_icmp_packet(sr, iphdr->ip_src, 11, 0, (uint8_t *)iphdr);
			return;
		}

		/* Recompute Cksum */
		iphdr->ip_sum = 0;
		iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));

		/* Destined to router */
		struct sr_if* if_walker = sr->if_list;
		while(if_walker)
		{
			if(if_walker->ip == iphdr->ip_dst)
			{
    			/* What is the protocol field in IP header? */
				
				/* ICMP Protocol */
				if (ip_protocol((uint8_t *) iphdr) == ip_protocol_icmp)
				{
					/* TODO: for now, we only handle echo request -> echo reply */

					/* Check that the packet is long enough for an IP header */
					minlength += sizeof(sr_icmp_hdr_t);
					if (len < minlength) 
					{
						printf("Failed to extract ICMP header, insufficient length\n");
						return;
					}

					/* Extract icmp header */
					sr_icmp_hdr_t * icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

					/* Echo Request */
					if (icmphdr->icmp_type == 8)
					{
						printf("Sending ICMP Echo Reply\n");
						send_echo_reply(sr, packet, len);
					}
					/* Any other ICMP Message*/
					/* FOR NOW!!! Drop packet */
					return;
				}
		
				/* UDP, TCP -> ICMP port unreachable */
				else
				{
					/* Reply ICMP destination port unreachable */
					printf("Sending ICMP3 Destination Port Unreachable\n");
					send_icmp_packet(sr, iphdr->ip_src, 3,3, (uint8_t *)iphdr);
				}
				return;
			}
			if_walker = if_walker->next;
		}

		/* Destined to others */
		/* Lookup Routing Table */
		struct sr_rt * rtIter = sr->routing_table;
		while(rtIter)
		{
			/* TODO: Fix longest prefix match */
			if(rtIter->dest.s_addr == iphdr->ip_dst)
			{
				/* Get gateway IP (next hop) */
				uint32_t gateIP = rtIter->gw.s_addr;

				/* Get dest MAC Address from ARP Cache */
				struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), gateIP);
				
				/* Get source MAC Address from outgoing interface */
				struct sr_if * outgoingIFace = sr_get_interface(sr, rtIter->interface);

				/* ARP Cache Hit */
				if(entry)
				{
					/* Send to Layer 2 */
					send_layer_2(sr, packet, len, outgoingIFace->name, entry->mac, ethertype_ip);
					free(entry);
					return;
				}

				/* ARP Cache Miss */
				struct sr_arpreq * req = sr_arpcache_queuereq( &(sr->cache), gateIP, packet, len, outgoingIFace->name);
       			handle_arpreq(sr, req);
				return;
			}
			rtIter = rtIter->next;
		}


		/* Routing entry not found -> ICMP network unreachable */
		/*printf("Routing entry not found\n");*/
		printf("Sending ICMP3 Network Unreachable\n");
		send_icmp_packet(sr, iphdr->ip_src, 3, 0, (uint8_t *)iphdr);
		return;
	}
	
	/* ARP Packet */
	else if (ethtype == ethertype_arp) 
	{ 
    	minlength += sizeof(sr_arp_hdr_t);
    	if (len < minlength)
      	{
      		printf("Failed to extract ARP header, insufficient length\n");
      		return;
      	}

      	/* Extract ARP Header */
      	sr_arp_hdr_t * arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      	/* Check if ARP request or reply */
      	/* ARP request */
      	if(ntohs(arphdr->ar_op) == 1)
      	{
      		/* Check if it is requesting one of our IP Addresses */
      		uint32_t targetIP = arphdr->ar_tip;

      		struct sr_if* if_walker = sr->if_list;
    		while(if_walker)
    		{
    			if(if_walker->ip == targetIP)
    			{
    				/* Send ARP reply */
    				send_arp_packet(sr, if_walker->name, arphdr->ar_sha, arphdr->ar_sip, arp_op_reply);
    				return;
    			}

       			if_walker = if_walker->next;
    		}

    		/* Not one of our IP Addresses, drop packet */
    		if(if_walker == NULL)
    			return;
      	}

      	/* ARP reply */
      	else if(ntohs(arphdr->ar_op) == 2)
      	{
      		/* Find the entry in the request queue that matches the source IP */
      		struct sr_arpreq * matching_req = sr_arpcache_insert( &(sr->cache), arphdr->ar_sha, arphdr->ar_sip);

      		/* If ip in ARP header matches none of our requests in the queue */
      		if(matching_req == NULL)
      		{
      			/* Drop this packet */
      			return;
      		}

      		/* matching_req now points to the sr_arpreq entry we need to add to cache 
      		   Send all packets waiting on this ARP Request*/
      		struct sr_packet * pkt;
      		for(pkt = matching_req->packets; pkt != NULL; pkt = pkt->next)
      		{
      			send_layer_2(sr, pkt->buf, pkt->len, pkt->iface, arphdr->ar_sha, ethertype_ip);
      		}

      		/* Remove the entry in the request queue */
      		sr_arpreq_destroy(&(sr->cache), matching_req);
      		return;
      	}
      	
      	else
      	{
      		printf("Unrecognized ARP Opcode\n");
      		return;
      	}
  	}
  	
  	else 
  	{
    	printf("Unrecognized Ethernet Type: %d\n", ethtype);
    	return;
  	}

  	
}/* end sr_ForwardPacket */

