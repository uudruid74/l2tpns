/*
 * Fernando ALVES 2014
 * Add functionality DHCPv6 to l2tpns.
 * GPL licenced
 */

#ifndef __DHCP6_H__
#define __DHCP6_H__

#define DHCP6_SOLICIT                 1
#define DHCP6_ADVERTISE               2
#define DHCP6_REQUEST                 3
#define DHCP6_CONFIRM                 4
#define DHCP6_RENEW                   5
#define DHCP6_REBIND                  6
#define DHCP6_REPLY                   7
#define DHCP6_RELEASE                 8
#define DHCP6_DECLINE                 9
#define DHCP6_RECONFIGURE            10
#define DHCP6_INFORMATION_REQUEST    11
#define DHCP6_RELAY_FORM             12
#define DHCP6_RELAY_REPL             13

#define D6_OPT_CLIENTID         1
#define D6_OPT_SERVERID         2
#define D6_OPT_IA_NA            3
#define D6_OPT_IA_TA            4
#define D6_OPT_IAADDR           5
#define D6_OPT_ORO              6
#define D6_OPT_PREFERENCE       7
#define D6_OPT_ELAPSED_TIME     8
#define D6_OPT_RELAY_MSG        9
#define D6_OPT_AUTH            11
#define D6_OPT_UNICAST         12
#define D6_OPT_STATUS_CODE     13
#define D6_OPT_RAPID_COMMIT    14
#define D6_OPT_USER_CLASS      15
#define D6_OPT_VENDOR_CLASS    16
#define D6_OPT_VENDOR_SPECIFIC 17
#define D6_OPT_INTERFACE_ID    18
#define D6_OPT_RECONF_MSG      19
#define D6_OPT_RECONF_ACCEPT   20
#define D6_OPT_DNS_SERVERS     23
#define D6_OPT_DOMAIN_LIST     24
#define D6_OPT_IA_PD           25
#define D6_OPT_IAPREFIX        26

#define D6_STATUS_Success          0
#define D6_STATUS_UnspecFail       1
#define D6_STATUS_NoAddrsAvail     2
#define D6_STATUS_NoBinding        3
#define D6_STATUS_NotOnLink        4
#define D6_STATUS_UseMulticast     5
#define D6_STATUS_NoPrefixAvail    6

#define DUID_LLT 1
#define DUID_EN  2
#define DUID_LL  3

 //~ 0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F 
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |         D6_OPT_IA_PD          |        Longueur d’option      |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      IAID (4 octets)                          |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      T1 (4 octets)                            |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      T2 (4 octets)                            |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      Options-IA_PD                            |
//~ .                                                               .
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Prefix for IA_PD
 //~ 0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F 
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |        OPTION_IAPREFIX        |         option-length         |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      preferred-lifetime                       |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                        valid-lifetime                         |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ | prefix-length |                                               |
//~ +-+-+-+-+-+-+-+-+          IPv6 prefix                          |
//~ |                           (16 octets)                         |
//~ |                                                               |
//~ |                                                               |
//~ |                                                               |
//~ |               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |               |                                               .
//~ +-+-+-+-+-+-+-+-+                                               .
//~ .                       IAprefix-options                        .
//~ .                                                               .
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 //~ 0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F 
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |         D6_OPT_IA_NA          |        Longueur d’option      |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      IAID (4 octets)                          |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      T1 (4 octets)                            |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      T2 (4 octets)                            |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      Options-IA_NA                            |
//~ .                                                               .
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 //~ 0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F 
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |         OPTION_IA_TA          |        Longueur d’option      |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      IAID (4 octets)                          |
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//~ |                      Options-IA_TA                            |
//~ .                                                               .
//~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct dhcp6_mess_hdr
{
	uint32_t type:8;
	uint32_t trans_id:24;
} __attribute__((packed));

struct dhcp6_opt_h
{
	uint16_t code;
	uint16_t len;
} __attribute__((packed));

struct dhcp6_duid
{
	uint16_t type;
	union {
		struct {
			uint16_t htype;
			uint32_t time;
			uint8_t addr[0];
		} __attribute__((packed)) llt;
		struct {
			uint32_t enterprise;
			uint8_t id[0];
		} __attribute__((packed)) en;
		struct {
			uint16_t htype;
			uint8_t addr[0];
		} __attribute__((packed)) ll;
		uint8_t raw[128];
	} u;
} __attribute__((packed));

struct dhcp6_opt_serverid
{
	struct dhcp6_opt_h opt_hdr;
	struct dhcp6_duid duid;
} __attribute__((packed));

struct dhcp6_opt_clientid
{
	struct dhcp6_opt_h opt_hdr;
	struct dhcp6_duid duid;
} __attribute__((packed));

struct dhcp6_opt_ia_na {
	struct dhcp6_opt_h hdr;
	uint32_t iaid;
	uint32_t T1;
	uint32_t T2;
} __attribute__((packed));

struct dhcp6_opt_ia_ta {
	struct dhcp6_opt_h hdr;
	uint32_t iaid;
} __attribute__((packed));

struct dhcp6_opt_ia_pd {
	struct dhcp6_opt_h hdr;
	uint32_t iaid;
	uint32_t T1;
	uint32_t T2;
} __attribute__((packed));

struct dhcp6_opt_ia_addr {
	struct dhcp6_opt_h hdr;
	struct in6_addr addr;
	uint32_t pref_lifetime;
	uint32_t valid_lifetime;
} __attribute__((packed));

struct dhcp6_opt_oro {
	struct dhcp6_opt_h hdr;
	uint16_t opt_demand[0];
} __attribute__((packed));

struct dhcp6_opt_status {
	struct dhcp6_opt_h hdr;
	uint16_t code;
} __attribute__((packed));

struct dhcp6_opt_preference {
	struct dhcp6_opt_h hdr;
	uint8_t pref;
} __attribute__((packed));

struct dhcp6_opt_ia_prefix {
	struct dhcp6_opt_h hdr;
	uint32_t pref_lifetime;
	uint32_t valid_lifetime;
	uint8_t prefix_len;
	struct in6_addr prefix;
} __attribute__((packed));

// dhcp6.c
void dhcpv6_process(uint16_t s, uint16_t t, uint8_t *p, uint16_t l);
void dhcpv6_init(void);

#endif /* __DHCP6_H__ */
