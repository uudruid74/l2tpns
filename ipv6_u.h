
#ifndef __IPV6_U_H__
#define __IPV6_U_H__

struct ipv6_pseudo_hdr {
	struct in6_addr src;
	struct in6_addr dest;
	uint32_t ulp_length;
	uint32_t zero    : 24;
	uint32_t nexthdr :  8;
} __attribute__((packed));

// dhcp6.c
uint16_t ipv6_checksum(struct ipv6_pseudo_hdr *p_pshdr, uint8_t *buff, int lenbuff);

#endif /* __IPV6_U_H__ */
