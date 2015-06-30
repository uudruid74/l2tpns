/*
 * Fernando ALVES 2014
 * GPL licenced
 */

#include <arpa/inet.h>

#include "ipv6_u.h"

uint16_t ipv6_checksum(struct ipv6_pseudo_hdr *p_pshdr, uint8_t *buff, int lenbuff)
{
	uint32_t sum = 0;
	uint16_t *ptrw = (uint16_t *) p_pshdr;
	uint16_t word16;
	int i;

	// Size pseudo header 40 byte (20 word)
	for (i = 0; i < (sizeof(*p_pshdr)/2); i++)
	{
		word16 = ntohs(*((uint16_t *)ptrw));
		sum += word16;
		++ptrw;
	}

	ptrw = (uint16_t *) buff;
	while (lenbuff > 1)
	{
		word16 = ntohs(*((uint16_t *) ptrw));
		sum += word16;
		++ptrw;
		lenbuff -= 2;
	}

	if (lenbuff > 0)
	{
		word16 = ntohs(*((uint8_t *) ptrw));
		sum += word16;
	}

	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement the result
	sum = ~sum;

	return htons((uint16_t) sum);
}
