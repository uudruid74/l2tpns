// L2TPNS: icmp

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip6.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <memory.h>

#include "dhcp6.h"
#include "l2tpns.h"
#include "ipv6_u.h"

static uint16_t _checksum(uint8_t *addr, int count);

void host_unreachable(in_addr_t destination, uint16_t id, in_addr_t source, uint8_t *packet, int packet_len)
{
	char buf[128] = {0};
	struct iphdr *iph;
	struct icmphdr *icmp;
	int len = 0, on = 1, icmp_socket;
	struct sockaddr_in whereto = {0};

	if ((icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return;

	setsockopt(icmp_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

	whereto.sin_addr.s_addr = destination;
	whereto.sin_family = AF_INET;

	iph = (struct iphdr *)(buf);
	len = sizeof(struct iphdr);
	icmp = (struct icmphdr *)(buf + len);
	len += sizeof(struct icmphdr);

	/* ip header + first 8 bytes of payload */
	if (packet_len > (sizeof(struct iphdr) + 8))
		packet_len = sizeof(struct iphdr) + 8;

	memcpy(buf + len, packet, packet_len);
	len += packet_len;

	iph->tos = 0;
	iph->id = id;
	iph->frag_off = 0;
	iph->ttl = 30;
	iph->check = 0;
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = 1;
	iph->check = 0;
	iph->daddr = destination;
	iph->saddr = source;

	iph->tot_len = ntohs(len);

	icmp->type = ICMP_DEST_UNREACH;
	icmp->code = ICMP_HOST_UNREACH;
	icmp->checksum = _checksum((uint8_t *) icmp, sizeof(struct icmphdr) + packet_len);

	iph->check = _checksum((uint8_t *) iph, sizeof(struct iphdr));

	sendto(icmp_socket, buf, len, 0, (struct sockaddr *)&whereto, sizeof(struct sockaddr));
	close(icmp_socket);
}

static uint16_t _checksum(uint8_t *addr, int count)
{
	register long sum = 0;

	for (; count > 1; count -= 2)
	{
		sum += ntohs(*(uint16_t *) addr);
		addr += 2;
	}

	if (count > 0) sum += *(unsigned char *)addr;

	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement the result
	sum = ~sum;

	return htons((uint16_t) sum);
}

struct nd_opt_rdnss_info_l2tpns
{
	uint8_t  nd_opt_rdnssi_type;
	uint8_t  nd_opt_rdnssi_len;
	uint16_t nd_opt_rdnssi_pref_flag_reserved;
	uint32_t nd_opt_rdnssi_lifetime;
	struct in6_addr nd_opt_rdnssi[0];
};

void send_ipv6_ra(sessionidt s, tunnelidt t, struct in6_addr *ip)
{
	struct nd_opt_prefix_info *pinfo;
	struct ip6_hdr *p_ip6_hdr;
	struct nd_router_advert *p_nra;
	struct nd_opt_rdnss_info_l2tpns *p_rdnss;
	uint8_t b[MAXETHER + 20];
	struct ipv6_pseudo_hdr pseudo_hdr;
	int l;

	LOG(3, s, t, "Sending IPv6 RA\n");

	memset(b, 0, sizeof(b));
	p_ip6_hdr = (struct ip6_hdr *) makeppp(b, sizeof(b), 0, 0, s, t, PPPIPV6, 0, 0, 0);

	if (!p_ip6_hdr)
	{
		LOG(3, s, t, "failed to send IPv6 RA\n");
		return;
	}

	p_ip6_hdr->ip6_vfc = 0x60;			// IPv6
	p_ip6_hdr->ip6_plen = 0;			// Length of payload (not header) (calculation below)
	p_ip6_hdr->ip6_nxt = IPPROTO_ICMPV6;			// icmp6 is next
	p_ip6_hdr->ip6_hlim = 255;			// Hop limit
	// IPv6 0xFE80::1
	inet_pton(AF_INET6, "FE80::1", &p_ip6_hdr->ip6_src.s6_addr);

	if (ip != NULL)
	{
		memcpy(p_ip6_hdr->ip6_dst.s6_addr, ip, 16);	// dest = ip
	}
	else
	{
		// FF02::1 - all hosts
		inet_pton(AF_INET6, "FF02::1", &p_ip6_hdr->ip6_dst.s6_addr);
	}

	// RA message after Ipv6 header
	p_nra = (struct nd_router_advert *) &p_ip6_hdr[1];
	p_nra->nd_ra_type = ND_ROUTER_ADVERT; // RA message (134)
	p_nra->nd_ra_code = 0;		// Code
	p_nra->nd_ra_cksum = 0;		// Checksum
	p_nra->nd_ra_curhoplimit = 64;		// Hop count
	p_nra->nd_ra_flags_reserved = (ND_RA_FLAG_MANAGED|ND_RA_FLAG_OTHER); // Flags
	p_nra->nd_ra_router_lifetime = 0xFFFF;	// Lifetime
	p_nra->nd_ra_reachable = 0;	// Reachable time
	p_nra->nd_ra_retransmit = 0;	// Retrans timer
	// Option PI after RA message (rfc4861)
	pinfo = (struct nd_opt_prefix_info *) &p_nra[1];
	pinfo->nd_opt_pi_type           = ND_OPT_PREFIX_INFORMATION;
	pinfo->nd_opt_pi_len            = 4;
	pinfo->nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
	pinfo->nd_opt_pi_valid_time     = htonl(2592000);
	pinfo->nd_opt_pi_preferred_time = htonl(604800);
	pinfo->nd_opt_pi_reserved2      = 0;
	pinfo->nd_opt_pi_prefix_len     = 64; // prefix length
	if (session[s].ipv6address.s6_addr[0])
	{
		// MSB 64bits of assigned IPv6 address to user (see radius attribut Framed-IPv6-Address)
		memcpy(&pinfo->nd_opt_pi_prefix, &session[s].ipv6address.s6_addr[0], 8);
	}
	else
		pinfo->nd_opt_pi_prefix     = config->ipv6_prefix;

	// Length of payload (not header)
	l = sizeof(*pinfo) + sizeof(*p_nra);

	if (config->default_ipv6_dns1.s6_addr32[0])
	{
		struct in6_addr *ptr_in6_addr;
		p_rdnss = (struct nd_opt_rdnss_info_l2tpns *) &pinfo[1];

		p_rdnss->nd_opt_rdnssi_type = 25; //RDNSS OPTION INFORMATION;
		p_rdnss->nd_opt_rdnssi_len = 3; // 1 + 2 * nb DNS
		p_rdnss->nd_opt_rdnssi_lifetime = htonl(config->dns6_lifetime);
		ptr_in6_addr = &p_rdnss->nd_opt_rdnssi[0];
		memcpy(ptr_in6_addr, &config->default_ipv6_dns1, sizeof(*ptr_in6_addr));

		l += sizeof(*p_rdnss)  + sizeof(*ptr_in6_addr);
		if (config->default_ipv6_dns2.s6_addr32[0])
		{
			ptr_in6_addr = &p_rdnss->nd_opt_rdnssi[1];
			memcpy(ptr_in6_addr, &config->default_ipv6_dns2, sizeof(*ptr_in6_addr));
			p_rdnss->nd_opt_rdnssi_len += 2; // 1 + 2 * nb DNS
			l += sizeof(*ptr_in6_addr);
		}
	}

	// Length of payload (not header)
	p_ip6_hdr->ip6_plen = htons(l);

	/* Use pseudo hearder for checksum calculation */
	memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
	memcpy(&pseudo_hdr.src, &p_ip6_hdr->ip6_src, 16);
	memcpy(&pseudo_hdr.dest, &p_ip6_hdr->ip6_dst, 16);
	pseudo_hdr.ulp_length = htonl(l); // Lenght whitout Ipv6 header
	pseudo_hdr.nexthdr = IPPROTO_ICMPV6;
	// Checksum is over the icmp6 payload plus the pseudo header
	p_nra->nd_ra_cksum = ipv6_checksum(&pseudo_hdr, (uint8_t *) p_nra, l);

	// Length + hearder length
	l += sizeof(*p_ip6_hdr);

	tunnelsend(b, l + (((uint8_t *) p_ip6_hdr)-b), t); // send it...
	return;
}
