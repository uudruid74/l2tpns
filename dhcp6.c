/*
 * Fernando ALVES 2014
 * Add functionality DHCPv6 to l2tpns.
 * GPL licenced
 */

#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "dhcp6.h"
#include "l2tpns.h"
#include "ipv6_u.h"

struct dhcp6_in_option
{
	struct dhcp6_mess_hdr *p_mess_hdr;
	struct dhcp6_opt_h *p_opt_clientid;
	struct dhcp6_opt_h *p_opt_serverid;
	struct dhcp6_opt_h *p_opt_ia_na;
	struct dhcp6_opt_h *p_opt_ia_ta;
	struct dhcp6_opt_h *p_opt_ia_pd;
	struct dhcp6_opt_h *p_opt_oro;
	struct dhcp6_opt_h *p_opt_rapidcommit;
};

static struct dhcp6_opt_serverid dhcp6_local_serverid;
static struct dhcp6_in_option list_option;

static int dhcpv6_format_dns_search_name(const char *strdns, uint8_t *buffer);

static void dhcp6_send_reply(sessionidt s, tunnelidt t, struct in6_addr *ip6_src)
{
	struct ip6_hdr *p_ip6_hdr;
	struct udphdr *p_udp;
	struct dhcp6_mess_hdr *p_mess_hdr;
	struct dhcp6_opt_h *p_opt;
	struct ipv6_pseudo_hdr pseudo_hdr;
	uint8_t b[MAXETHER + 20];
	int len;

	memset(b, 0, sizeof(b));
	p_ip6_hdr = (struct ip6_hdr *) makeppp(b, sizeof(b), 0, 0, s, t, PPPIPV6, 0, 0, 0);

	// IPv6 Header
	p_ip6_hdr->ip6_vfc = 0x60;			// IPv6
	p_ip6_hdr->ip6_plen = 0;			// Length of payload (not header) (calculation below)
	p_ip6_hdr->ip6_nxt = IPPROTO_UDP;			// icmp6 is next
	p_ip6_hdr->ip6_hlim = 1;			// Hop limit
	// IPv6 Src FE02::1:2
	inet_pton(AF_INET6, "FE02::1:2", &p_ip6_hdr->ip6_src.s6_addr);
	// IPv6 Dest
	memcpy(&p_ip6_hdr->ip6_dst.s6_addr, ip6_src, sizeof(p_ip6_hdr->ip6_dst.s6_addr));

	// UDP Header
	p_udp = (struct udphdr *) &p_ip6_hdr[1];
	p_udp->source = htons(547);
	p_udp->dest = htons(546);
	p_udp->len = 0; // Length udp size_udp_header + data (calculation below)
	p_udp->check = 0; // checksum (calculation below with ip pseudo header)

	// DHCPv6 msg header
	p_mess_hdr = (struct dhcp6_mess_hdr *) &p_udp[1];
	if (list_option.p_mess_hdr->type == DHCP6_SOLICIT)
		p_mess_hdr->type = list_option.p_opt_rapidcommit ? DHCP6_REPLY : DHCP6_ADVERTISE;
	else
		p_mess_hdr->type = DHCP6_REPLY;

	p_mess_hdr->trans_id = list_option.p_mess_hdr->trans_id;

	// DHCPv6 options header
	p_opt = (struct dhcp6_opt_h *) &p_mess_hdr[1];
	memcpy(p_opt, &dhcp6_local_serverid, ntohs(dhcp6_local_serverid.opt_hdr.len) + sizeof(dhcp6_local_serverid.opt_hdr)); // ServerID
	p_opt = (struct dhcp6_opt_h *) (((uint8_t *) p_opt) + ntohs(p_opt->len) + sizeof(*p_opt)); // next option

	if (list_option.p_opt_clientid)
	{
		memcpy(p_opt, list_option.p_opt_clientid, ntohs(list_option.p_opt_clientid->len) + sizeof(*p_opt)); // ClientID
		p_opt = (struct dhcp6_opt_h *) (((uint8_t *) p_opt) + ntohs(p_opt->len) + sizeof(*p_opt)); // next option
	}

	if (list_option.p_opt_ia_pd && (list_option.p_mess_hdr->type != DHCP6_INFORMATION_REQUEST))
	{
		p_opt->code = htons(D6_OPT_IA_PD); // D6_OPT_IA_PD
		((struct dhcp6_opt_ia_pd *)p_opt)->iaid = ((struct dhcp6_opt_ia_pd *)list_option.p_opt_ia_pd)->iaid;
		((struct dhcp6_opt_ia_pd *)p_opt)->T1 = (config->dhcp6_preferred_lifetime > 0) ? htonl(config->dhcp6_preferred_lifetime/2) : 0xFFFFFFFF;
		((struct dhcp6_opt_ia_pd *)p_opt)->T2 = (config->dhcp6_preferred_lifetime > 0) ? htonl((config->dhcp6_preferred_lifetime*4)/5) : 0xFFFFFFFF;

		if ((list_option.p_mess_hdr->type == DHCP6_RENEW) && session[s].dhcpv6_prefix_iaid != ((struct dhcp6_opt_ia_pd *)list_option.p_opt_ia_pd)->iaid)
		{
			p_opt->len = htons(sizeof(struct dhcp6_opt_ia_pd) - sizeof(*p_opt) + sizeof(struct dhcp6_opt_status));
			p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_ia_pd *)p_opt)[1];

			((struct dhcp6_opt_status *)p_opt)->hdr.code = htons(D6_OPT_STATUS_CODE);
			((struct dhcp6_opt_status *)p_opt)->hdr.len = htons(2);
			((struct dhcp6_opt_status *)p_opt)->code = htons(D6_STATUS_NoBinding);
			p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_status *)p_opt)[1]; // next option
		}
		else
		{
			struct dhcp6_opt_h *p_opt_head;
			int r;
			uint16_t lenopt;

			if (list_option.p_mess_hdr->type == DHCP6_REQUEST || list_option.p_opt_rapidcommit)
			{
				session[s].dhcpv6_prefix_iaid = ((struct dhcp6_opt_ia_pd *)list_option.p_opt_ia_pd)->iaid;
			}

			p_opt_head = p_opt;
			lenopt = sizeof(struct dhcp6_opt_ia_pd) - sizeof(*p_opt);

			p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_ia_pd *)p_opt)[1];

			for (r = 0; r < MAXROUTE6 && session[s].route6[r].ipv6route.s6_addr[0] && session[s].route6[r].ipv6prefixlen; r++)
			{
				((struct dhcp6_opt_ia_prefix *)p_opt)->hdr.code = htons(D6_OPT_IAPREFIX);
				((struct dhcp6_opt_ia_prefix *)p_opt)->hdr.len = htons(sizeof(struct dhcp6_opt_ia_prefix) - sizeof(*p_opt));
				((struct dhcp6_opt_ia_prefix *)p_opt)->pref_lifetime= (config->dhcp6_preferred_lifetime > 0) ? htonl(config->dhcp6_preferred_lifetime) : 0xFFFFFFFF;
				((struct dhcp6_opt_ia_prefix *)p_opt)->valid_lifetime= (config->dhcp6_valid_lifetime > 0) ? htonl(config->dhcp6_valid_lifetime) : 0xFFFFFFFF;
				((struct dhcp6_opt_ia_prefix *)p_opt)->prefix_len = session[s].route6[r].ipv6prefixlen;
				((struct dhcp6_opt_ia_prefix *)p_opt)->prefix = session[s].route6[r].ipv6route;

				 p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_ia_prefix *)p_opt)[1]; // next option
				 lenopt += sizeof(struct dhcp6_opt_ia_prefix);
			}
			p_opt_head->len = htons(lenopt);
		}
	}

	if (list_option.p_opt_ia_na && (list_option.p_mess_hdr->type != DHCP6_INFORMATION_REQUEST))
	{
		p_opt->code = htons(D6_OPT_IA_NA); // D6_OPT_IA_NA
		((struct dhcp6_opt_ia_na *)p_opt)->iaid =  ((struct dhcp6_opt_ia_na *)list_option.p_opt_ia_na)->iaid;
		((struct dhcp6_opt_ia_na *)p_opt)->T1 = (config->dhcp6_preferred_lifetime > 0) ? htonl(config->dhcp6_preferred_lifetime/2) : 0xFFFFFFFF;
		((struct dhcp6_opt_ia_na *)p_opt)->T2 = (config->dhcp6_preferred_lifetime > 0) ? htonl((config->dhcp6_preferred_lifetime*4)/5) : 0xFFFFFFFF;

		if ((list_option.p_mess_hdr->type == DHCP6_RENEW) && session[s].dhcpv6_iana_iaid != ((struct dhcp6_opt_ia_na *)list_option.p_opt_ia_na)->iaid)
		{
			p_opt->len = htons(sizeof(struct dhcp6_opt_ia_na) - sizeof(*p_opt) + sizeof(struct dhcp6_opt_status));
			p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_ia_na *)p_opt)[1];

			((struct dhcp6_opt_status *)p_opt)->hdr.code = htons(D6_OPT_STATUS_CODE);
			((struct dhcp6_opt_status *)p_opt)->hdr.len = htons(2);
			((struct dhcp6_opt_status *)p_opt)->code = htons(D6_STATUS_NoBinding);
			p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_status *)p_opt)[1]; // next option
		}
		else
		{
			in_addr_t addr_ipv4;

			if (list_option.p_mess_hdr->type == DHCP6_REQUEST || list_option.p_opt_rapidcommit)
			{
				session[s].dhcpv6_iana_iaid = ((struct dhcp6_opt_ia_na *)list_option.p_opt_ia_na)->iaid;
			}

			p_opt->len = htons(sizeof(struct dhcp6_opt_ia_na) - sizeof(*p_opt) + sizeof(struct dhcp6_opt_ia_addr));
			p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_ia_na *)p_opt)[1];

			((struct dhcp6_opt_ia_addr *)p_opt)->hdr.code = htons(D6_OPT_IAADDR);
			((struct dhcp6_opt_ia_addr *)p_opt)->hdr.len = htons(sizeof(struct dhcp6_opt_ia_addr) - sizeof(*p_opt));

			if (session[s].ipv6address.s6_addr[0])
			{
				memcpy(&((struct dhcp6_opt_ia_addr *)p_opt)->addr, &session[s].ipv6address, 16); // copy ipv6 prefix
			}
			else
			{
				memcpy(&((struct dhcp6_opt_ia_addr *)p_opt)->addr, &config->ipv6_prefix, 8); // copy prefix 64
				addr_ipv4 = htonl(session[s].ip);
				memcpy(&((struct dhcp6_opt_ia_addr *)p_opt)->addr.s6_addr[8], &addr_ipv4, 4); // copy ipv4
			}

			((struct dhcp6_opt_ia_addr *)p_opt)->pref_lifetime= (config->dhcp6_preferred_lifetime > 0) ? htonl(config->dhcp6_preferred_lifetime) : 0xFFFFFFFF;
			((struct dhcp6_opt_ia_addr *)p_opt)->valid_lifetime= (config->dhcp6_valid_lifetime > 0) ? htonl(config->dhcp6_valid_lifetime) : 0xFFFFFFFF;

			 p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_ia_addr *)p_opt)[1]; // next option
		}
	}

	if (list_option.p_opt_ia_ta && (list_option.p_mess_hdr->type != DHCP6_INFORMATION_REQUEST))
	{
		p_opt->code = htons(D6_OPT_IA_TA); // D6_OPT_IA_TA
		p_opt->len = htons(sizeof(struct dhcp6_opt_ia_ta) - sizeof(*p_opt) + sizeof(struct dhcp6_opt_status));
		((struct dhcp6_opt_ia_ta *)p_opt)->iaid = ((struct dhcp6_opt_ia_ta *)list_option.p_opt_ia_ta)->iaid;
		p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_ia_ta *)p_opt)[1];
		((struct dhcp6_opt_status *)p_opt)->hdr.code = htons(D6_OPT_STATUS_CODE);
		((struct dhcp6_opt_status *)p_opt)->hdr.len = htons(2);
		((struct dhcp6_opt_status *)p_opt)->code = htons(D6_STATUS_UnspecFail);
		p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_status *)p_opt)[1]; // next option
	}

	if (list_option.p_opt_oro)
	{
		int countopt;
		uint16_t *ptrw;
		struct in6_addr *ptr_in6_addr;

		for (countopt = ntohs(list_option.p_opt_oro->len)/2, ptrw = (uint16_t *)((struct dhcp6_opt_oro *)list_option.p_opt_oro)->opt_demand; countopt; countopt--, ptrw++)
		{
			if (ntohs(*ptrw) == D6_OPT_DNS_SERVERS)
			{
				if (config->default_ipv6_dns1.s6_addr[0])
				{
					p_opt->code = htons(D6_OPT_DNS_SERVERS); // D6_OPT_DNS_SERVERS
					p_opt->len = htons(sizeof(*ptr_in6_addr));
					ptr_in6_addr = (struct in6_addr *) &p_opt[1];
					memcpy(ptr_in6_addr, &config->default_ipv6_dns1, sizeof(*ptr_in6_addr));

					if (config->default_ipv6_dns2.s6_addr[0])
					{
						p_opt->len = htons(2*sizeof(*ptr_in6_addr));
						ptr_in6_addr = &ptr_in6_addr[1];
						memcpy(ptr_in6_addr, &config->default_ipv6_dns2, sizeof(*ptr_in6_addr));
					}

					p_opt = (struct dhcp6_opt_h *) &ptr_in6_addr[1]; // next option
				}
			}

			if (ntohs(*ptrw) == D6_OPT_DOMAIN_LIST)
			{
				if (*config->default_ipv6_domain_list)
				{
					uint8_t buffer[255];
					int len = dhcpv6_format_dns_search_name(config->default_ipv6_domain_list, buffer);

					if (len > 0)
					{
						p_opt->code = htons(D6_OPT_DOMAIN_LIST); // D6_OPT_DOMAIN_LIST
						p_opt->len = htons(len);
						memcpy((char *)&p_opt[1], buffer, len);

						p_opt = (struct dhcp6_opt_h *) (((uint8_t *) &p_opt[1]) + len); // next option
					}
				}
			}
		}
	}

	if (list_option.p_opt_rapidcommit && (list_option.p_mess_hdr->type == DHCP6_SOLICIT))
	{
		p_opt->code = htons(D6_OPT_RAPID_COMMIT); // D6_OPT_RAPID_COMMIT
		p_opt->len = 0;
		p_opt = &p_opt[1]; // next option
	}

	p_opt->code = htons(D6_OPT_PREFERENCE); // D6_OPT_PREFERENCE
	p_opt->len = htons(1);
	((struct dhcp6_opt_preference *)p_opt)->pref = 255;
	p_opt = (struct dhcp6_opt_h *) &((struct dhcp6_opt_preference *)p_opt)[1]; // next option

	// calculation of lenght
	len = ((uint8_t *) p_opt) - ((uint8_t *) p_udp);
	p_ip6_hdr->ip6_plen = p_udp->len = htons(len);

	/* Use pseudo hearder for checksum calculation */
	memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
	memcpy(&pseudo_hdr.src, &p_ip6_hdr->ip6_src, 16);
	memcpy(&pseudo_hdr.dest, &p_ip6_hdr->ip6_dst, 16);
	pseudo_hdr.ulp_length = htonl(len); // Lenght whitout Ipv6 header
	pseudo_hdr.nexthdr = IPPROTO_UDP;
	// Checksum is over the udp payload plus the pseudo header
	p_udp->check = ipv6_checksum(&pseudo_hdr, (uint8_t *) p_udp, len);

	// Add ipv6 header to length
	len += sizeof(*p_ip6_hdr);
	LOG(3, s, t, "Send DHCPv6 message %s\n", (p_mess_hdr->type == DHCP6_REPLY) ? "REPLY" : "ADVERTISE");
	tunnelsend(b, len + (((uint8_t *) p_ip6_hdr)-b), t); // send it...
}

static char * get_msg_type(uint8_t type)
{
	switch(type)
	{
		case DHCP6_SOLICIT:
		{
			return "Solicit";
		}
		break;

		case DHCP6_REQUEST:
			return "Request";
		break;

		case DHCP6_RENEW:
			return "Renew";
		break;

		case DHCP6_INFORMATION_REQUEST:
			return "Information Request";
		break;

		case DHCP6_REBIND:
			return "Rebind";
		break;

		case DHCP6_RELEASE:
			return "Release";
		break;

		case DHCP6_DECLINE:
			return "Decline";
		break;

		default:
			return "Unknown";
		break;
	}
}

void dhcpv6_process(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
	struct ip6_hdr *p_ip6_hdr_in;
	struct dhcp6_mess_hdr *p_mess_hdr;
	struct dhcp6_opt_h *p_opt;
	uint8_t *p_end;
	uint16_t len;

	CSTAT(dhcpv6_process);

	p_ip6_hdr_in = (struct ip6_hdr *) p;
	p_mess_hdr = (struct dhcp6_mess_hdr *) (p + 48);

	LOG(3, s, t, "Got DHCPv6 message Type: %s(%d)\n", get_msg_type(p_mess_hdr->type), p_mess_hdr->type);

	if (!session[s].route6[0].ipv6route.s6_addr[0] || !session[s].route6[0].ipv6prefixlen)
		return;

	p_opt = (struct dhcp6_opt_h *) &p_mess_hdr[1];
	p_end = ((uint8_t *)p_ip6_hdr_in) + ntohs(p_ip6_hdr_in->ip6_plen) + sizeof(*p_ip6_hdr_in);
	memset(&list_option, 0, sizeof(list_option));
	list_option.p_mess_hdr = p_mess_hdr;
	while (((uint8_t *)p_opt) < p_end)
	{
		switch(ntohs(p_opt->code))
		{
			case D6_OPT_CLIENTID:
				list_option.p_opt_clientid = p_opt;
				LOG(3, s, t, "......Option D6_OPT_CLIENTID\n");
			break;
			case D6_OPT_SERVERID:
				list_option.p_opt_serverid = p_opt;
				LOG(3, s, t, "......Option D6_OPT_SERVERID\n");
			break;
			case D6_OPT_RAPID_COMMIT:
				list_option.p_opt_rapidcommit = p_opt;
				LOG(3, s, t, "......Option D6_OPT_RAPID_COMMIT\n");
			break;
			case D6_OPT_IA_NA:
				list_option.p_opt_ia_na = p_opt;
				LOG(3, s, t, "......Option D6_OPT_IA_NA\n");
			break;
			case D6_OPT_IA_TA:
				list_option.p_opt_ia_ta = p_opt;
				LOG(3, s, t, "......Option D6_OPT_IA_TA\n");
			break;
			case D6_OPT_ORO:
				list_option.p_opt_oro = p_opt;
				LOG(3, s, t, "......Option D6_OPT_ORO\n");
			break;
			case D6_OPT_IA_PD:
				list_option.p_opt_ia_pd = p_opt;
				LOG(3, s, t, "......Option D6_OPT_IA_PD\n");
			break;
			case D6_OPT_ELAPSED_TIME:
				LOG(3, s, t, "......Option D6_OPT_ELAPSED_TIME\n");
			break;

			default:
				LOG(3, s, t, "......DHCPv6 option: %d\n", ntohs(p_opt->code));
			break;
		}
		p_opt = (struct dhcp6_opt_h *)(((uint8_t *) p_opt) + ntohs(p_opt->len) + sizeof(*p_opt));
	}

	switch(p_mess_hdr->type)
	{
		case DHCP6_SOLICIT:
		{
			if (!list_option.p_opt_clientid)
			{
				LOG(3, s, t, "DHCPv6: error no Client-ID\n");
				return;
			}
			else if (list_option.p_opt_rapidcommit)
			{
				if (!session[s].dhcpv6_client_id.opt_hdr.len)
				{
					len = ntohs(list_option.p_opt_clientid->len);

					if ((len > 0) && (len <= sizeof(struct dhcp6_duid)))
					{
						memcpy(&session[s].dhcpv6_client_id, list_option.p_opt_clientid, sizeof(struct dhcp6_opt_h) + len);
					}
					else
					{
						LOG(3, s, t, "DHCPv6: Error malformed Client-ID option\n");
						return;
					}
				}
				else if (session[s].dhcpv6_client_id.opt_hdr.len != list_option.p_opt_clientid->len || 
							memcmp(&session[s].dhcpv6_client_id, list_option.p_opt_clientid, sizeof(struct dhcp6_opt_h) + ntohs(list_option.p_opt_clientid->len)))
				{
					LOG(3, s, t, "DHCPv6: Error unmatched Client-ID option\n");
					return;
				}
			}

			if (list_option.p_opt_serverid)
			{
				LOG(3, s, t, "DHCPv6: Error unexpected Server-ID option on Solicit\n");
				return;
			}

			dhcp6_send_reply(s, t, &p_ip6_hdr_in->ip6_src);
		}
		break;

		case DHCP6_REQUEST:
		{
			if (!list_option.p_opt_clientid)
			{
				LOG(3, s, t, "DHCPv6: error no Client-ID\n");
				return;
			}

			if (!list_option.p_opt_serverid)
			{
				LOG(3, s, t, "DHCPv6: error no Server-ID\n");
				return;
			}
			else if (dhcp6_local_serverid.opt_hdr.len != list_option.p_opt_serverid->len || 
					memcmp(&dhcp6_local_serverid, list_option.p_opt_serverid, sizeof(struct dhcp6_opt_h) + ntohs(list_option.p_opt_serverid->len)))
			{
				LOG(3, s, t, "DHCPv6: Error unmatched Server-ID option\n");
				return;
			}

			if (!session[s].dhcpv6_client_id.opt_hdr.len)
			{
				len = ntohs(list_option.p_opt_clientid->len);

				if ((len > 0) && (len <= sizeof(struct dhcp6_duid)))
				{
					memcpy(&session[s].dhcpv6_client_id, list_option.p_opt_clientid, sizeof(struct dhcp6_opt_h) + len);
				}
				else
				{
					LOG(3, s, t, "DHCPv6: Error malformed Client-ID option\n");
					return;
				}
			}
			else if ( session[s].dhcpv6_client_id.opt_hdr.len != list_option.p_opt_clientid->len || 
						memcmp(&session[s].dhcpv6_client_id, list_option.p_opt_clientid, sizeof(struct dhcp6_opt_h) + ntohs(list_option.p_opt_clientid->len)))
			{
				LOG(3, s, t, "DHCPv6: Error unmatched Client-ID option\n");
				return;
			}

			dhcp6_send_reply(s, t, &p_ip6_hdr_in->ip6_src);
		}
		break;

		case DHCP6_RENEW:
		{
			if (!list_option.p_opt_clientid)
			{
				LOG(3, s, t, "DHCPv6: error no Client-ID\n");
				return;
			}
			else if ( session[s].dhcpv6_client_id.opt_hdr.len != list_option.p_opt_clientid->len || 
						memcmp(&session[s].dhcpv6_client_id, list_option.p_opt_clientid, sizeof(struct dhcp6_opt_h) + ntohs(list_option.p_opt_clientid->len)))
			{
				LOG(3, s, t, "DHCPv6: Error unmatched Client-ID option\n");
				return;
			}

			if (!list_option.p_opt_serverid)
			{
				LOG(3, s, t, "DHCPv6: error no Server-ID\n");
				return;
			}
			else if (dhcp6_local_serverid.opt_hdr.len != list_option.p_opt_serverid->len || 
					memcmp(&dhcp6_local_serverid, list_option.p_opt_serverid, sizeof(struct dhcp6_opt_h) + ntohs(list_option.p_opt_serverid->len)))
			{
				LOG(3, s, t, "DHCPv6: Error unmatched Server-ID option\n");
				return;
			}

			dhcp6_send_reply(s, t, &p_ip6_hdr_in->ip6_src);
		}
		break;

		case DHCP6_INFORMATION_REQUEST:
		{
			if (!list_option.p_opt_clientid)
			{
				LOG(3, s, t, "DHCPv6: error no Client-ID\n");
				return;
			}

			dhcp6_send_reply(s, t, &p_ip6_hdr_in->ip6_src);
		}
		break;

		case DHCP6_REBIND:
		{
		}
		break;

		case DHCP6_RELEASE:
		{
		}
		break;

		case DHCP6_DECLINE:
		{
		}
		break;

		default:
		break;
	}

	return;
}

static int dhcpv6_format_dns_search_name(const char *strdns, uint8_t *buffer)
{
	int n = strlen(strdns);
	const char *ptr;

	if (strdns[n - 1] == '.') n++;
	else n += 2;

	if (n > 255) {
		LOG(3, 0, 0, "DHCPv6: DNS search '%s' is too long\n", strdns);
		return 0;
	}

	while (1)
	{
		ptr = strchr(strdns, '.');

		if (!ptr) ptr = strchr(strdns, 0);

		if (ptr - strdns > 63)
		{
			LOG(3, 0, 0, "DHCPv6: DNS search '%s' is invalid\n", strdns);
			return 0;
		}

		*buffer = ptr - strdns;
		memcpy(buffer + 1, strdns, ptr - strdns);
		buffer += 1 + (ptr - strdns);
		strdns = ptr + 1;

		if (!*ptr || !*strdns)
		{
			*buffer = 0;
			break;
		}
	}

	return n;
}

void dhcpv6_init(void)
{
	uint32_t id;

	dhcp6_local_serverid.opt_hdr.code = htons(D6_OPT_SERVERID);
	dhcp6_local_serverid.opt_hdr.len = htons(4 + sizeof(id));
	dhcp6_local_serverid.duid.type = htons(DUID_LL);
	dhcp6_local_serverid.duid.u.ll.htype = htons(27);

	if (config->dhcp6_server_duid)
		id = htobe32(config->dhcp6_server_duid);
	else
		id = htobe32(0xFDFDFAFA);

	memcpy(dhcp6_local_serverid.duid.u.ll.addr, &id, sizeof(id));
}
