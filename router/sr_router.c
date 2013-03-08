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

/* Method to send ICMP packet (fills IP header, sends to send_layer_2) to an interface. */
void send_icmp_packet(struct sr_instance* sr, char* interface/* lent */, void * ether_src, void * ether_dest, 
    					uint32_t ip_src, uint32_t ip_dst, uint8_t icmp_type, uint8_t icmp_code)
{
	// TODO: Handle sr_icmp_t3_hdr as well

	/* Create packet to hold ethernet header, ip header, and icmp header */
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	uint8_t * packet = (uint8_t) malloc ((size_t) len);

	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_icmp_hdr_t));

	/* Fill out ICMP header */
	icmp_hdr->icmp_type = htons(icmp_type);
	icmp_hdr->icmp_code = htons(icmp_code);
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum((void *) icmp_hdr, sizeof(sr_icmp_hdr_t));

	/* Fill out IP header */
	// TODO: What do we do with all the other ip_hdr fields, including ttl??
	ip_hdr->ip_p = ip_protocol_icmp;
	ip_hdr->ip_src = ip_src;
	ip_hdr->ip_dst = ip_dst;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum((void *) ip_hdr, sizeof(sr_ip_hdr_t));

	/* Send packet with space for ethernet to send_layer_2() to actually send packet */
	send_layer_2(sr, packet, len, interface, ether_src, ether_dst, ethertype_ip);

	return;
}

/* Method to send packets (with space for ethernet header) to an interface. */
void send_layer_2(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, 
					char* interface/* lent */, void * src, void * dest, uint16_t type)
{
	sr_ethernet_hdr_t * eth_hdr = packet;

	/* Modify Ethernet header */
	memcpy(eth_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, src, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(type);

	/* DEBUG: Print reply packet */
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
	int minlength = sizeof(sr_ethernet_hdr_t);
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
		if(iphdr->ip_ttl <= 0)
		{
			/* Send ICMP Message */
			send_icmp_packet(sr, interface, recievingInterface->addr, eth_hdr->ether_shost, 
    					ip_hdr->ip_dst, ip_hdr->ip_src, 11, 0)
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
    			uint8_t icmp_type;
    			uint8_t icmp_code;


    			/* What is the protocol field in IP header? */
				
				/* ICMP Protocol */
				if (ip_protocol((uint8_t *) iphdr) == ip_protocol_icmp)
				{
					/* TODO: for now, we only handle echo request -> echo reply */

					/* Echo Request */
					if (ntohs(icmphdr->icmp_type) == 8)
					{
						icmp_type = 0;
						icmp_code = 0;
					}

					/* Any other ICMP Message*/
					else
					{
						/* FOR NOW!!! Drop packet */
						return;
					}
				}
		
				/* UDP, TCP -> ICMP port unreachable */
				else
				{
					/* Reply ICMP destination port unreachable */
					icmp_type = 3;
					icmp_code = 3;

				}

				/* Send ICMP Packet */
				send_icmp_packet(sr, if_walker->name, recievingInterface->addr, eth_hdr->ether_shost, 
    								ip_hdr->ip_dst, ip_hdr->ip_src, icmp_type, icmp_code);

				return;
			}

			if_walker = if_walker->next;
		}

		/* Destined to others */
		/* Lookup Routing Table */
		struct sr_rt * rtIter = sr->routing_table;
		while(rtIter)
		{
			if(rtIter->dest.s_addr == iphdr->ip_dst)
			{
				printf("Routing Table match\n");

				/* Get gateway IP (next hop) */
				uint32_t gateIP = rtIter->gw.s_addr;

				/* Get dest MAC Address from ARP Cache */
				struct sr_arpentry * entry = sr_arpcache_lookup(sr->cache, gateIP);
				
				/* Get source MAC Address from outgoing interface */
				struct sr_if * outgoingIFace = sr_get_interface(sr, rtIter->interface);

				/* ARP Cache Hit */
				if(entry)
				{
					/* Send to Layer 2 */
					send_layer_2(sr, packet, len, outgoingIFace->name,outgoingIFace->addr, entry->mac, ethertype_ip);
					free(entry);
					return
				}

				/* ARP Cache Miss */
				


			}
			rtIter = rtIter->next;
		}

		/* Routing entry not found -> ICMP network unreachable */
		printf("Routing entry not found\n");
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
    				/* Build an ARP reply packet */
    				
    				/* Set ARP opcode to Reply */
    				arphdr->ar_op = htons(2);
    				
    				/* Set target MAC Address and ip to the source address and ip */
    				memcpy(arphdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);
    				arphdr->ar_tip = arphdr->ar_sip;

    				/* Set source MAC Address and ip to the interface */
    				memcpy(arphdr->ar_sha, if_walker->addr, ETHER_ADDR_LEN);
    				arphdr->ar_sip = if_walker->ip;

    				/* Set Ethernet Header */
    				memcpy(eth_hdr->ether_dhost, arphdr->ar_tha, ETHER_ADDR_LEN);
    				memcpy(eth_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);

    				
    				sr_send_packet(sr, packet, len, if_walker->name);
    				send_layer_2(sr, packet, len, if_walker->name, if_walker->addr, arphdr->ar_tha, ethertype_arp);
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

