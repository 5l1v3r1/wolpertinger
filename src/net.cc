/*
 * This file is part of the wolpertinger project.
 *
 * Copyright (C) 2003-2009 Christian Eichelmann <ceichelmann@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <asm/types.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "shared.h"
#include "ipc.h"
#include "net.h"

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

/* global informations */
extern struct global_informations global;

/*
 * returns char* string of IPv4-Address for given 32bit int address value
 * use this for pretty printing
 */
char *ntoa(uint32_t addr)
{
        static char buffer[18];
        sprintf(buffer, "%d.%d.%d.%d",
                (addr & 0x000000FF)      ,
                (addr & 0x0000FF00) >>  8,
                (addr & 0x00FF0000) >> 16,
                (addr & 0xFF000000) >> 24);
        return buffer;
}

/*
 * returns char* string of Mac-Adress for given eth_addr_t* address value
 * use this for pretty printing
 */
char *mtoa(eth_addr_t *hwaddr)
{
        static char buffer[20];
        sprintf(buffer, "%-2.2x:%-2.2x:%-2.2x:%-2.2x:%-2.2x:%-2.2x",
                hwaddr->data[0], hwaddr->data[1], hwaddr->data[2],
                hwaddr->data[3], hwaddr->data[4], hwaddr->data[5]);
        return buffer;
}

/*
 * returns MAC address of the given interface char* string as type eth_addr_t* 
 */
eth_addr_t *gethwaddr(char *iface) {
    int s;
    struct ifreq ifr;
    struct eth_addr *res;
    res = (struct eth_addr *) safe_zalloc(ETH_ADDR_LEN);
    
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        MSG(MSG_WARN, "failed to open socket: %s\n", strerror(errno));
        return NULL;
    }
    
    strcpy(ifr.ifr_name, iface);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        MSG(MSG_WARN, "failed to ioctl: %s\n", strerror(errno));
        return NULL;
    }

    if (close(s) < 0) {
        MSG(MSG_WARN, "failed to close socket: %s\n", strerror(errno));
        return NULL;
    }

    memcpy(res, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);
    return res;
}

/*
 * returns 32bit int value of source IP address which will be used to connect to given
 * (32bit int value) destination ip address, i.e. Which IP do I use to ping this target?
 */
uint32_t getsrcip(uint32_t dstip)
{
	int s;
    struct sockaddr_in name;
    struct sockaddr_in dest;
    socklen_t n = sizeof(struct sockaddr_in);

    dest.sin_family = AF_INET;
    dest.sin_port = htons(2000);
    dest.sin_addr.s_addr = dstip;

    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        MSG(MSG_WARN, "failed to open socket: %s\n", strerror(errno));
        return 0;
    }
	
	if (connect(s, (struct sockaddr *) &dest, n) < 0) {
        MSG(MSG_WARN, "failed to connect to socket: %s\n", strerror(errno));
		return 0;
    }

	if (getsockname(s, (struct sockaddr *) &name, &n) < 0) {
        MSG(MSG_WARN, "failed to getsockname: %s\n", strerror(errno));
		return 0;
    }

    if (close(s) < 0) {
        MSG(MSG_WARN, "failed to close socket: %s\n", strerror(errno));
        return 0;
    }

    return name.sin_addr.s_addr;    
}

/*
 * Sends a single ARP paket on the given interface name (char*), asking for the given destination ip (32bit int)
 * and requesting answers to the given source ip (32bit int, use getsrcip to get this) and source MAC (eth_addr_t *,
 * use gethwaddr to get this).
 * 
 * This function will segfault horribly if you are not root!
 *
 * You need to listen with pcap etc. for an answer to the ARP request if you want to use it (Linux will not add gratutious ARP responses
 * to its ARP table by default, see /proc/sys/net/ipv4/conf/all/arp_accept for the current setting...)
 * 
 * TODO: function is not used atm.
 */
void send_arp_request(const char *iface, uint32_t dstip, uint32_t srcip, eth_addr_t *srcmac)
{
    eth_t *eth = eth_open(iface);

	u_char frame[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];

    //printf("srcmac @ %p with value %s\n", (void *) srcmac, mtoa(srcmac));

	eth_pack_hdr(frame, ETH_ADDR_BROADCAST, *srcmac, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(frame + ETH_HDR_LEN, ARP_OP_REQUEST,
	    *srcmac, srcip, ETH_ADDR_BROADCAST, dstip);

	eth_send(eth, frame, sizeof(frame));

    eth = eth_close(eth);
}
