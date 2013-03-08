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
		if(iphdr->ip_ttl == 0)
		{
			/* TODO: Send ICMP Message */
			return;
		}

		/* Recompute Cksum TODO: Make sure cksum is computed correctly*/
		iphdr->ip_sum = cksum(iphdr,sizeof(sr_ip_hdr_t));

		/* Check Destination IP */
		uint32_t destIP = iphdr->ip_dst;
		struct sr_if* if_walker = sr->if_list;

		/* Destined to router */
		while(if_walker)
		{
			if(if_walker->ip == destIP)
			{
    			/* What is the protocol field in IP header? */
				if (ip_protocol((uint8_t *) iphdr) == ip_protocol_icmp)
				{
					/* TODO: ICMP processing */
				}
				else
				{
					/* ICMP port unreachable */
				}

				return;
			}

			if_walker = if_walker->next;
		}

		/* Destined to others */
		/* Lookup Routing Table */
		sr_rt * rtIter = sr->routing_table;
		while(rtIter)
		{
			if(rtIter->dest == destIP)
			{
				
			}
			
		}
		/* Routing entry not found -> ICMP network unreachable */
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
    				/* Build a reply packet */
    				
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

    				/* DEBUG: Print reply packet */
    				print_hdrs(packet, (uint32_t) len);

    				/* Send a reply packet */
    				sr_send_packet(sr, packet, len, if_walker->name);
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

