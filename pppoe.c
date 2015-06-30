/*
 * Fernando ALVES 2013
 * Add functionality "server pppoe" to l2tpns.
 * inspiration pppoe.c of accel-ppp
 * GPL licenced
 */

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if_pppox.h>

#include "dhcp6.h"
#include "l2tpns.h"
#include "cluster.h"
#include "constants.h"
#include "md5.h"
#include "util.h"

int pppoediscfd = -1;
int pppoesessfd = -1;

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* PPPoE codes */
#define CODE_PADI           0x09
#define CODE_PADO           0x07
#define CODE_PADR           0x19
#define CODE_PADS           0x65
#define CODE_PADT           0xA7
#define CODE_SESS           0x00

/* PPPoE Tags */
#define TAG_END_OF_LIST        0x0000
#define TAG_SERVICE_NAME       0x0101
#define TAG_AC_NAME            0x0102
#define TAG_HOST_UNIQ          0x0103
#define TAG_AC_COOKIE          0x0104
#define TAG_VENDOR_SPECIFIC    0x0105
#define TAG_RELAY_SESSION_ID   0x0110
#define TAG_SERVICE_NAME_ERROR 0x0201
#define TAG_AC_SYSTEM_ERROR    0x0202
#define TAG_GENERIC_ERROR      0x0203

static char *code_pad[] = {
	"PADI",
	"PADO",
	"PADR",
	"PADS",
	"PADT",
	"SESS",
	NULL
};

enum
{
	INDEX_PADI = 0,
	INDEX_PADO,
	INDEX_PADR,
	INDEX_PADS,
	INDEX_PADT,
	INDEX_SESS
};

// set up pppoe discovery socket
static void init_pppoe_disc(void)
{
	int on = 1;
	struct ifreq ifr;
	struct sockaddr_ll sa;

	memset(&ifr, 0, sizeof(ifr));
	memset(&sa, 0, sizeof(sa));

	pppoediscfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC));
	if (pppoediscfd < 0)
	{
		LOG(0, 0, 0, "Error pppoe: socket: %s\n", strerror(errno));
		exit(1);
	}

	fcntl(pppoediscfd, F_SETFD, fcntl(pppoediscfd, F_GETFD) | FD_CLOEXEC);

	if (setsockopt(pppoediscfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)))
	{
		LOG(0, 0, 0, "Error pppoe: setsockopt(SO_BROADCAST): %s\n", strerror(errno));
		exit(1);
	}

	assert(strlen(ifr.ifr_name) < sizeof(config->pppoe_if_to_bind) - 1);
	if (*config->pppoe_if_to_bind)
		strncpy(ifr.ifr_name, config->pppoe_if_to_bind, IFNAMSIZ);

	if (ioctl(pppoediscfd, SIOCGIFHWADDR, &ifr))
	{
		LOG(0, 0, 0, "Error pppoe: ioctl(SIOCGIFHWADDR): %s\n", strerror(errno));
		exit(1);
	}

	if ((ifr.ifr_hwaddr.sa_data[0] & 1) != 0)
	{
		LOG(0, 0, 0, "Error pppoe: interface %s has not unicast address\n", config->pppoe_if_to_bind);
		exit(1);
	}

	memcpy(config->pppoe_hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (ioctl(pppoediscfd, SIOCGIFMTU, &ifr))
	{
		LOG(0, 0, 0, "Error pppoe: ioctl(SIOCGIFMTU): %s\n", strerror(errno));
		exit(1);
	}

	if (ifr.ifr_mtu < ETH_DATA_LEN)
		LOG(0, 0, 0, "Error pppoe: interface %s has MTU of %i, should be %i\n", config->pppoe_if_to_bind, ifr.ifr_mtu, ETH_DATA_LEN);

	if (ioctl(pppoediscfd, SIOCGIFINDEX, &ifr))
	{
		LOG(0, 0, 0, "Error pppoe: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_PPP_DISC);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if (bind(pppoediscfd, (struct sockaddr *)&sa, sizeof(sa)))
	{
		LOG(0, 0, 0, "Error pppoe: bind: %s\n", strerror(errno));
		exit(1);
	}

	if (fcntl(pppoediscfd, F_SETFL, O_NONBLOCK))
	{
		LOG(0, 0, 0, "Error pppoe: failed to set nonblocking mode: %s\n", strerror(errno));
		exit(1);
	}

}

// set up pppoe session socket
static void init_pppoe_sess(void)
{
	int on = 1;
	struct ifreq ifr;
	struct sockaddr_ll sa;

	memset(&ifr, 0, sizeof(ifr));
	memset(&sa, 0, sizeof(sa));

	pppoesessfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_SES));
	if (pppoesessfd < 0)
	{
		LOG(0, 0, 0, "Error pppoe: socket: %s\n", strerror(errno));
		exit(1);
	}

	fcntl(pppoesessfd, F_SETFD, fcntl(pppoesessfd, F_GETFD) | FD_CLOEXEC);

	if (setsockopt(pppoesessfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)))
	{
		LOG(0, 0, 0, "Error pppoe: setsockopt(SO_BROADCAST): %s\n", strerror(errno));
		exit(1);
	}

	assert(strlen(ifr.ifr_name) < sizeof(config->pppoe_if_to_bind) - 1);
	if (*config->pppoe_if_to_bind)
		strncpy(ifr.ifr_name, config->pppoe_if_to_bind, IFNAMSIZ);

	if (ioctl(pppoesessfd, SIOCGIFHWADDR, &ifr))
	{
		LOG(0, 0, 0, "Error pppoe: ioctl(SIOCGIFHWADDR): %s\n", strerror(errno));
		exit(1);
	}

	if ((ifr.ifr_hwaddr.sa_data[0] & 1) != 0)
	{
		LOG(0, 0, 0, "Error pppoe: interface %s has not unicast address\n", config->pppoe_if_to_bind);
		exit(1);
	}

	memcpy(config->pppoe_hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (ioctl(pppoesessfd, SIOCGIFMTU, &ifr))
	{
		LOG(0, 0, 0, "Error pppoe: ioctl(SIOCGIFMTU): %s\n", strerror(errno));
		exit(1);
	}

	if (ifr.ifr_mtu < ETH_DATA_LEN)
		LOG(0, 0, 0, "Error pppoe: interface %s has MTU of %i, should be %i\n", config->pppoe_if_to_bind, ifr.ifr_mtu, ETH_DATA_LEN);

	if (ioctl(pppoesessfd, SIOCGIFINDEX, &ifr))
	{
		LOG(0, 0, 0, "Error pppoe: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_PPP_SES);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if (bind(pppoesessfd, (struct sockaddr *)&sa, sizeof(sa)))
	{
		LOG(0, 0, 0, "Error pppoe: bind: %s\n", strerror(errno));
		exit(1);
	}

	if (fcntl(pppoesessfd, F_SETFL, O_NONBLOCK))
	{
		LOG(0, 0, 0, "Error pppoe: failed to set nonblocking mode: %s\n", strerror(errno));
		exit(1);
	}
}

// set up pppoe discovery/session socket
void init_pppoe(void)
{
	tunnelidt t = TUNNEL_ID_PPPOE;

	init_pppoe_disc();
	init_pppoe_sess();

	// Reserve the a pseudo tunnel for pppoe server
	if (t > config->cluster_highest_tunnelid)
		config->cluster_highest_tunnelid = t;

	memset(&tunnel[t], 0, sizeof(tunnel[t]));
	tunnel[t].state = TUNNELOPEN;
	STAT(tunnel_created);
}

char * get_string_codepad(uint8_t codepad)
{
	char * ptrch = NULL;
	switch(codepad)
	{
		case CODE_PADI:
		ptrch = code_pad[INDEX_PADI];
		break;

		case CODE_PADO:
		ptrch = code_pad[INDEX_PADO];
		break;

		case CODE_PADR:
		ptrch = code_pad[INDEX_PADR];
		break;

		case CODE_PADS:
		ptrch = code_pad[INDEX_PADS];
		break;

		case CODE_PADT:
		ptrch = code_pad[INDEX_PADT];
		break;

		case CODE_SESS:
		ptrch = code_pad[INDEX_SESS];
		break;
	}
	
	return ptrch;
}

static uint8_t * setup_header(uint8_t *pack, const uint8_t *src, const uint8_t *dst, int code, uint16_t sid, uint16_t h_proto)
{
	uint8_t * p;

	// 14 bytes ethernet Header + 6 bytes header pppoe
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	memcpy(ethhdr->h_source, src, ETH_ALEN);
	memcpy(ethhdr->h_dest, dst, ETH_ALEN);
	ethhdr->h_proto = htons(h_proto);

	hdr->ver = 1;
	hdr->type = 1;
	hdr->code = code;
	hdr->sid = htons(sid);
	hdr->length = 0;

	p = (uint8_t *)(pack + ETH_HLEN + sizeof(*hdr));

	return p;
}

static void add_tag(uint8_t *pack, int type, const uint8_t *data, int len)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));

	tag->tag_type = htons(type);
	tag->tag_len = htons(len);
	memcpy(tag->tag_data, data, len);

	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + len);
}

static void add_tag2(uint8_t *pack, const struct pppoe_tag *t)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));

	memcpy(tag, t, sizeof(*t) + ntohs(t->tag_len));
	
	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + ntohs(t->tag_len));
}

static void pppoe_disc_send(const uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n, s;

	s = ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length);

	LOG(3, 0, 0, "SENT pppoe_disc: Code %s to %s\n", get_string_codepad(hdr->code), fmtMacAddr(ethhdr->h_dest));
	LOG_HEX(5, "pppoe_disc_send", pack, s);

	n = write(pppoediscfd, pack, s);
	if (n < 0 )
		LOG(0, 0, 0, "pppoe: write: %s\n", strerror(errno));
	else if (n != s) {
		LOG(0, 0, 0, "pppoe: short write %i/%i\n", n,s);
	}
}

void pppoe_sess_send(const uint8_t *pack, uint16_t l, tunnelidt t)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n;
	uint16_t sizeppp;
	sessionidt s;

	if (t != TUNNEL_ID_PPPOE)
	{
		LOG(3, 0, t, "ERROR pppoe_sess_send: Tunnel %d is not a tunnel pppoe\n", t);
		return;
	}

	s = ntohs(hdr->sid);
	if (session[s].tunnel != t)
	{
		LOG(3, s, t, "ERROR pppoe_sess_send: Session is not a session pppoe\n");
		return;
	}

	if (l < (ETH_HLEN + sizeof(*hdr) + 3))
	{
		LOG(0, s, t, "ERROR pppoe_sess_send: packet too small for pppoe sent (size=%d)\n", l);
		return;
	}

	// recalculate the ppp frame length
	sizeppp = l - (ETH_HLEN + sizeof(*hdr));
	hdr->length = htons(sizeppp);

	LOG_HEX(5, "pppoe_sess_send", pack, l);

	n = write(pppoesessfd, pack, l);
	if (n < 0 )
		LOG(0, s, t, "pppoe_sess_send: write: %s\n", strerror(errno));
	else if (n != l)
		LOG(0, s, t, "pppoe_sess_send: short write %i/%i\n", n,l);
}

static void pppoe_send_err(const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, int code, int tag_type)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, config->pppoe_hwaddr, addr, code, 0, ETH_P_PPP_DISC);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)config->pppoe_ac_name, strlen(config->pppoe_ac_name));
	add_tag(pack, tag_type, NULL, 0);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	pppoe_disc_send(pack);
}

// generate cookie
static void pppoe_gen_cookie(const uint8_t *serv_hwaddr, const uint8_t *client_hwaddr, uint8_t *out)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, config->l2tp_secret, strlen(config->l2tp_secret));
	MD5_Update(&ctx, (void *) serv_hwaddr, ETH_ALEN);
	MD5_Update(&ctx, (void *) client_hwaddr, ETH_ALEN);
	MD5_Final(out, &ctx);
}

// check cookie
static int pppoe_check_cookie(const uint8_t *serv_hwaddr, const uint8_t *client_hwaddr, uint8_t *cookie)
{
	hasht hash;

	pppoe_gen_cookie(serv_hwaddr, client_hwaddr, hash);

	return memcmp(hash, cookie, 16);
}

static void pppoe_send_PADO(const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	uint8_t pack[ETHER_MAX_LEN];
	hasht hash;

	setup_header(pack, config->pppoe_hwaddr, addr, CODE_PADO, 0, ETH_P_PPP_DISC);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)config->pppoe_ac_name, strlen(config->pppoe_ac_name));

	if (service_name)
		add_tag2(pack, service_name);

	pppoe_gen_cookie(config->pppoe_hwaddr, addr, hash);
	add_tag(pack, TAG_AC_COOKIE, hash, 16);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	pppoe_disc_send(pack);
}

static void pppoe_send_PADS(uint16_t sid, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, config->pppoe_hwaddr, addr, CODE_PADS, sid, ETH_P_PPP_DISC);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)config->pppoe_ac_name, strlen(config->pppoe_ac_name));

	add_tag2(pack, service_name);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	pppoe_disc_send(pack);
}

static void pppoe_send_PADT(uint16_t sid)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, config->pppoe_hwaddr, session[sid].src_hwaddr, CODE_PADT, sid, ETH_P_PPP_DISC);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)config->pppoe_ac_name, strlen(config->pppoe_ac_name));

	LOG(3, sid, session[sid].tunnel, "pppoe: Sent PADT\n");

	pppoe_disc_send(pack);
}

void pppoe_shutdown_session(sessionidt s)
{

	if (session[s].tunnel != TUNNEL_ID_PPPOE)
	{
		LOG(3, s, session[s].tunnel, "ERROR pppoe_shutdown_session: Session is not a session pppoe\n");
		return;
	}

	pppoe_send_PADT(s);
}

static void pppoe_recv_PADI(uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	int n, service_match = 0;
	int len;

	if (hdr->sid)
		return;

	len = ntohs(hdr->length);
	for (n = 0; n < len; n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (n + sizeof(*tag) + ntohs(tag->tag_len) > len)
			return;
		switch (ntohs(tag->tag_type))
		{
			case TAG_END_OF_LIST:
				break;
			case TAG_SERVICE_NAME:
				if (config->pppoe_only_equal_svc_name && *config->pppoe_service_name && !tag->tag_len)
				{
					break;
				}
				else if (*config->pppoe_service_name && tag->tag_len)
				{
					if (ntohs(tag->tag_len) != strlen(config->pppoe_service_name))
						break;
					if (memcmp(tag->tag_data, config->pppoe_service_name, ntohs(tag->tag_len)))
						break;
					service_name_tag = tag;
					service_match = 1;
				}
				else
				{
					service_name_tag = tag;
					service_match = 1;
				}
				break;
			case TAG_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case TAG_RELAY_SESSION_ID:
				relay_sid_tag = tag;
				break;
		}
	}

	if (!service_match)
	{
		LOG(3, 0, 0, "pppoe: discarding PADI packet (Service-Name mismatch)\n");
		return;
	}

	pppoe_send_PADO(ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);
}

static void pppoe_recv_PADR(uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *ac_cookie_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	int n, service_match = 0;
	uint16_t sid;

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN))
	{
		LOG(1, 0, 0, "Rcv pppoe: discard PADR (destination address is broadcast)\n");
		return;
	}

	if (hdr->sid)
	{
		LOG(1, 0, 0, "Rcv pppoe: discarding PADR packet (sid is not zero)\n");
		return;
	}

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len))
	{
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		switch (ntohs(tag->tag_type))
		{
			case TAG_END_OF_LIST:
				break;
			case TAG_SERVICE_NAME:
				service_name_tag = tag;
				if (tag->tag_len == 0)
					service_match = 1;
				else if (*config->pppoe_service_name)
				{
					if (ntohs(tag->tag_len) != strlen(config->pppoe_service_name))
						break;
					if (memcmp(tag->tag_data, config->pppoe_service_name, ntohs(tag->tag_len)))
						break;
					service_match = 1;
				}
				else
				{
					service_match = 1;
				}
				break;
			case TAG_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case TAG_AC_COOKIE:
				ac_cookie_tag = tag;
				break;
			case TAG_RELAY_SESSION_ID:
				relay_sid_tag = tag;
				break;
		}
	}

	if (!service_match)
	{
		LOG(3, 0, 0, "pppoe: Service-Name mismatch\n");
		pppoe_send_err(ethhdr->h_source, host_uniq_tag, relay_sid_tag, CODE_PADS, TAG_SERVICE_NAME_ERROR);
		return;
	}

	if (!ac_cookie_tag)
	{
		LOG(3, 0, 0, "pppoe: discard PADR packet (no AC-Cookie tag present)\n");
		return;
	}

	if (ntohs(ac_cookie_tag->tag_len) != 16)
	{
		LOG(3, 0, 0, "pppoe: discard PADR packet (incorrect AC-Cookie tag length)\n");
		return;
	}

	if (pppoe_check_cookie(ethhdr->h_dest, ethhdr->h_source, (uint8_t *) ac_cookie_tag->tag_data))
	{
		LOG(3, 0, 0, "pppoe: discard PADR packet (incorrect AC-Cookie)\n");
		return;
	}

	sid = sessionfree;
	sessionfree = session[sid].next;
	memset(&session[sid], 0, sizeof(session[0]));

	if (sid > config->cluster_highest_sessionid)
		config->cluster_highest_sessionid = sid;

	session[sid].opened = time_now;
	session[sid].tunnel = TUNNEL_ID_PPPOE;
	session[sid].last_packet = session[sid].last_data = time_now;

	//strncpy(session[sid].called, called, sizeof(session[sid].called) - 1);
	//strncpy(session[sid].calling, calling, sizeof(session[sid].calling) - 1);

	session[sid].ppp.phase = Establish;
	session[sid].ppp.lcp = Starting;

	session[sid].magic = time_now; // set magic number
	session[sid].mru = PPPoE_MRU; // default

	// start LCP
	sess_local[sid].lcp_authtype = config->radius_authprefer;
	sess_local[sid].ppp_mru = MRU;

	// Set multilink options before sending initial LCP packet
	sess_local[sid].mp_mrru = 1614;
	sess_local[sid].mp_epdis = ntohl(config->iftun_address ? config->iftun_address : my_address);

	memcpy(session[sid].src_hwaddr, ethhdr->h_source, ETH_ALEN);
	pppoe_send_PADS(sid, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);

	sendlcp(sid, session[sid].tunnel);
	change_state(sid, lcp, RequestSent);

}

static void pppoe_recv_PADT(uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN))
	{
		LOG(3, 0, 0, "pppoe: discard PADT (destination address is broadcast)\n");
		return;
	}

	if (hdr->sid)
	{
		if ((hdr->sid < MAXSESSION) && (session[hdr->sid].tunnel == TUNNEL_ID_PPPOE))
			sessionshutdown(hdr->sid, "Client shutdown", CDN_ADMIN_DISC, 0);
	}
}

// fill in a PPPOE message with a PPP frame,
// returns start of PPP frame
uint8_t *pppoe_makeppp(uint8_t *b, int size, uint8_t *p, int l, sessionidt s, tunnelidt t,
						uint16_t mtype, uint8_t prio, bundleidt bid, uint8_t mp_bits)
{
	uint16_t type = mtype;
	uint8_t *start = b;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(b + ETH_HLEN);

	if (t != TUNNEL_ID_PPPOE)
		return NULL;

	if (size < 28) // Need more space than this!!
	{
		LOG(0, s, t, "pppoe_makeppp buffer too small for pppoe header (size=%d)\n", size);
		return NULL;
	}

	// 14 bytes ethernet Header + 6 bytes header pppoe
	b = setup_header(b, config->pppoe_hwaddr, session[s].src_hwaddr, CODE_SESS, s, ETH_P_PPP_SES);

	// Check whether this session is part of multilink
	if (bid)
	{
		if (bundle[bid].num_of_links > 1)
			type = PPPMP; // Change PPP message type to the PPPMP
		else
			bid = 0;
	}

	*(uint16_t *) b = htons(type);
	b += 2;
	hdr->length += 2;

	if (bid)
	{
		// Set the sequence number and (B)egin (E)nd flags
		if (session[s].mssf)
		{
			// Set the multilink bits
			uint16_t bits_send = mp_bits;
			*(uint16_t *) b = htons((bundle[bid].seq_num_t & 0x0FFF)|bits_send);
			b += 2;
			hdr->length += 2;
		}
		else
		{
			*(uint32_t *) b = htonl(bundle[bid].seq_num_t);
			// Set the multilink bits
			*b = mp_bits;
			b += 4;
			hdr->length += 4;
		}

		bundle[bid].seq_num_t++;

		// Add the message type if this fragment has the begin bit set
		if (mp_bits & MP_BEGIN)
		{
			//*b++ = mtype; // The next two lines are instead of this 
			*(uint16_t *) b = htons(mtype); // Message type
			b += 2;
			hdr->length += 2;
		}
	}

	if ((b - start) + l > size)
	{
		LOG(0, s, t, "pppoe_makeppp would overflow buffer (size=%d, header+payload=%td)\n", size, (b - start) + l);
		return NULL;
	}

	// Copy the payload
	if (p && l)
	{
		memcpy(b, p, l);
		hdr->length += l;
	}

	return b;
}

// fill in a PPPOE message with a PPP frame,
// returns start of PPP frame
//(note: THIS ROUTINE WRITES TO p[-28]).
uint8_t *opt_pppoe_makeppp(uint8_t *p, int l, sessionidt s, tunnelidt t, uint16_t mtype, uint8_t prio, bundleidt bid, uint8_t mp_bits)
{
	uint16_t type = mtype;
	uint16_t hdrlen = l;
	uint8_t *b = p;
	struct pppoe_hdr *hdr;

	if (t != TUNNEL_ID_PPPOE)
		return NULL;

	// Check whether this session is part of multilink
	if (bid)
	{
		if (bundle[bid].num_of_links > 1)
			type = PPPMP; // Change PPP message type to the PPPMP
		else
			bid = 0;
	}

	if (bid)
	{
		// Add the message type if this fragment has the begin bit set
		if (mp_bits & MP_BEGIN)
		{
			b -= 2;
			*(uint16_t *) b = htons(mtype); // Message type
		}

		// Set the sequence number and (B)egin (E)nd flags
		if (session[s].mssf)
		{
			// Set the multilink bits
			uint16_t bits_send = mp_bits;
			b -= 2;
			*(uint16_t *) b = htons((bundle[bid].seq_num_t & 0x0FFF)|bits_send);
		}
		else
		{
			b -= 4;
			*(uint32_t *) b = htonl(bundle[bid].seq_num_t);
			// Set the multilink bits
			*b = mp_bits;
		}

		bundle[bid].seq_num_t++;
	}

	b -= 2;
	*(uint16_t *) b = htons(type);

	// Size ppp packet
	hdrlen += (p - b);

	// 14 bytes ethernet Header + 6 bytes header pppoe
	b -= (ETH_HLEN + sizeof(*hdr));
	setup_header(b, config->pppoe_hwaddr, session[s].src_hwaddr, CODE_SESS, s, ETH_P_PPP_SES);
	hdr = (struct pppoe_hdr *)(b + ETH_HLEN);
	// Store length on header pppoe
	hdr->length = hdrlen;

	return b;
}

// pppoe discovery recv data
void process_pppoe_disc(uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	LOG(3, 0, 0, "RCV pppoe_disc: Code %s from %s\n", get_string_codepad(hdr->code), fmtMacAddr(ethhdr->h_source));
	LOG_HEX(5, "PPPOE Disc", pack, size);

	if (!config->cluster_iam_master)
	{
		if (hdr->code == CODE_PADI)
			return; // Discard because the PADI is received by all (PADI is a broadcast diffusion)

		master_forward_pppoe_packet(pack, size, hdr->code);
		return;
	}

	if (size < (ETH_HLEN + sizeof(*hdr)))
	{
		LOG(1, 0, 0, "Error pppoe_disc: short packet received (%i)\n", size);
		return;
	}

	if (memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) && memcmp(ethhdr->h_dest, config->pppoe_hwaddr, ETH_ALEN))
	{
		LOG(1, 0, 0, "Error pppoe_disc: h_dest != bc_addr and  h_dest != config->pppoe_hwaddr\n");
		return;
	}

	if (!memcmp(ethhdr->h_source, bc_addr, ETH_ALEN))
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (source address is broadcast)\n");
		return;
	}

	if ((ethhdr->h_source[0] & 1) != 0)
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (host address is not unicast)\n");
		return;
	}

	if (size < ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length))
	{
		LOG(1, 0, 0, "Error pppoe_disc: short packet received\n");
		return;
	}

	if (hdr->ver != 1)
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (unsupported version %i)\n", hdr->ver);
		return;
	}

	if (hdr->type != 1)
	{
		LOG(1, 0, 0, "Error pppoe_disc: discarding packet (unsupported type %i)\n", hdr->type);
		return;
	}

	switch (hdr->code) {
		case CODE_PADI:
			pppoe_recv_PADI(pack, size);
			break;
		case CODE_PADR:
			pppoe_recv_PADR(pack, size);
			break;
		case CODE_PADT:
			pppoe_recv_PADT(pack);
			break;
	}
}

// Forward from pppoe to l2tp remote LNS
static void pppoe_forwardto_session_rmlns(uint8_t *pack, int size, sessionidt sess, uint16_t proto)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	uint16_t lppp = ntohs(hdr->length);
	uint16_t ll2tp = lppp + 6;
	uint8_t *pppdata = (uint8_t *) hdr->tag;
	uint8_t *pl2tp = pppdata - 6;
	uint8_t *p = pl2tp;
	uint16_t t = 0, s = 0;

	s = session[sess].forwardtosession;
	if (session[s].forwardtosession != sess)
	{
		LOG(3, sess, session[sess].tunnel, "pppoe: Link Session (%u) broken\n", s);
		return;
	}

	t = session[s].tunnel;
	if (t >= MAXTUNNEL)
	{
		LOG(1, s, t, "pppoe: Session with invalid tunnel ID\n");
		return;
	}

	if (!tunnel[t].isremotelns)
	{
		LOG(3, sess, session[sess].tunnel, "pppoe: Link Tunnel/Session (%u/%u) broken\n", s, t);
		return;
	}

	// First word L2TP options (with no options)
	*(uint16_t *) p = htons(0x0002);
	p += 2;
	*(uint16_t *) p = htons(tunnel[t].far); // tunnel
	p += 2;
	*(uint16_t *) p = htons(session[s].far); // session
	p += 2;

	if ((proto == PPPIP) || (proto == PPPMP) ||(proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0]))
	{
		session[sess].last_packet = session[sess].last_data = time_now;
		// Update STAT IN
		increment_counter(&session[sess].cin, &session[sess].cin_wrap, ll2tp);
		session[sess].cin_delta += ll2tp;
		session[sess].pin++;
		sess_local[sess].cin += ll2tp;
		sess_local[sess].pin++;

		session[s].last_data = time_now;
		// Update STAT OUT
		increment_counter(&session[s].cout, &session[s].cout_wrap, ll2tp); // byte count
		session[s].cout_delta += ll2tp;
		session[s].pout++;
		sess_local[s].cout += ll2tp;
		sess_local[s].pout++;
	}
	else
		session[sess].last_packet = time_now;

	tunnelsend(pl2tp, ll2tp, t); // send it...
}

// Forward from l2tp to pppoe
// (note: THIS ROUTINE WRITES TO pack[-20]).
void pppoe_forwardto_session_pppoe(uint8_t *pack, int size, sessionidt sess, uint16_t proto)
{
	uint16_t t = 0, s = 0;
	uint16_t lpppoe = size - 2;
	uint8_t *p = pack + 2; // First word L2TP options

	LOG(5, sess, session[sess].tunnel, "Forwarding data session to pppoe session %u\n", session[sess].forwardtosession);

	s = session[sess].forwardtosession;
	t = session[s].tunnel;

	if (*pack & 0x40)
	{	// length
		p += 2;
		lpppoe -= 2;
	}

	*(uint16_t *) p = htons(tunnel[t].far); // tunnel
	p += 2;
	*(uint16_t *) p = htons(session[s].far); // session
	p += 2;
	lpppoe -= 4;

	if (*pack & 0x08)
	{   // ns/nr
		*(uint16_t *) p = htons(tunnel[t].ns); // sequence
		p += 2;
		*(uint16_t *) p = htons(tunnel[t].nr); // sequence
		p += 2;
		lpppoe -= 4;
	}

	if (lpppoe > 2 && p[0] == 0xFF && p[1] == 0x03)
	{
		// HDLC address header, discard in pppoe
		p += 2;
		lpppoe -= 2;
	}

	lpppoe += (ETH_HLEN + sizeof(struct pppoe_hdr));
	p -= (ETH_HLEN + sizeof(struct pppoe_hdr));

	// 14 bytes ethernet Header + 6 bytes header pppoe
	setup_header(p, config->pppoe_hwaddr, session[s].src_hwaddr, CODE_SESS, s, ETH_P_PPP_SES);

	if ((proto == PPPIP) || (proto == PPPMP) ||(proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0]))
	{
		session[sess].last_packet = session[sess].last_data = time_now;
		// Update STAT IN
		increment_counter(&session[sess].cin, &session[sess].cin_wrap, lpppoe);
		session[sess].cin_delta += lpppoe;
		session[sess].pin++;
		sess_local[sess].cin += lpppoe;
		sess_local[sess].pin++;

		session[s].last_data = time_now;
		// Update STAT OUT
		increment_counter(&session[s].cout, &session[s].cout_wrap, lpppoe); // byte count
		session[s].cout_delta += lpppoe;
		session[s].pout++;
		sess_local[s].cout += lpppoe;
		sess_local[s].pout++;
	}
	else
		session[sess].last_packet = time_now;

	tunnelsend(p, lpppoe, t); // send it....
}

void process_pppoe_sess(uint8_t *pack, int size)
{
	//struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	uint16_t lppp = ntohs(hdr->length);
	uint8_t *pppdata = (uint8_t *) hdr->tag;
	uint16_t proto, sid, t;

	sid = ntohs(hdr->sid);
	t = TUNNEL_ID_PPPOE;

	LOG_HEX(5, "RCV PPPOE Sess", pack, size);

	if (sid >= MAXSESSION)
	{
		LOG(0, sid, t, "Received pppoe packet with invalid session ID\n");
		STAT(tunnel_rx_errors);
		return;
	}

	if (session[sid].tunnel != t)
	{
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }

		LOG(1, sid, t, "ERROR process_pppoe_sess: Session is not a session pppoe\n");
		return;
	}

	if (hdr->ver != 1)
	{
		LOG(3, sid, t, "Error process_pppoe_sess: discarding packet (unsupported version %i)\n", hdr->ver);
		return;
	}

	if (hdr->type != 1)
	{
		LOG(3, sid, t, "Error process_pppoe_sess: discarding packet (unsupported type %i)\n", hdr->type);
		return;
	}

	if (lppp > 2 && pppdata[0] == 0xFF && pppdata[1] == 0x03)
	{	// HDLC address header, discard
		LOG(5, sid, t, "pppoe_sess: HDLC address header, discard\n");
		pppdata += 2;
		lppp -= 2;
	}
	if (lppp < 2)
	{
		LOG(3, sid, t, "Error process_pppoe_sess: Short ppp length %d\n", lppp);
		return;
	}
	if (*pppdata & 1)
	{
		proto = *pppdata++;
		lppp--;
	}
	else
	{
		proto = ntohs(*(uint16_t *) pppdata);
		pppdata += 2;
		lppp -= 2;
	}

	if (session[sid].forwardtosession)
	{	// Must be forwaded to a remote lns tunnel l2tp
		pppoe_forwardto_session_rmlns(pack, size, sid, proto);
		return;
	}

	if (proto == PPPPAP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processpap(sid, t, pppdata, lppp);
	}
	else if (proto == PPPCHAP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processchap(sid, t, pppdata, lppp);
	}
	else if (proto == PPPLCP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processlcp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIPCP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipcp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIPV6CP && config->ipv6_prefix.s6_addr[0])
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipv6cp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPCCP)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processccp(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIP)
	{
		session[sid].last_packet = session[sid].last_data = time_now;
		if (session[sid].walled_garden && !config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipin(sid, t, pppdata, lppp);
	}
	else if (proto == PPPMP)
	{
		session[sid].last_packet = session[sid].last_data = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processmpin(sid, t, pppdata, lppp);
	}
	else if (proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0])
	{
		session[sid].last_packet = session[sid].last_data = time_now;
		if (session[sid].walled_garden && !config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		processipv6in(sid, t, pppdata, lppp);
	}
	else if (session[sid].ppp.lcp == Opened)
	{
		session[sid].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_pppoe_packet(pack, size, hdr->code); return; }
		protoreject(sid, t, pppdata, lppp, proto);
	}
	else
	{
		LOG(3, sid, t, "process_pppoe_sess: Unknown PPP protocol 0x%04X received in LCP %s state\n",
			proto, ppp_state(session[sid].ppp.lcp));
	}
}

void pppoe_send_garp()
{
	int s;
	struct ifreq ifr;
	uint8_t mac[6];

	if (!*config->pppoe_if_to_bind)
		return;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		LOG(0, 0, 0, "Error creating socket for GARP: %s\n", strerror(errno));
		return;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, config->pppoe_if_to_bind, sizeof(ifr.ifr_name) - 1);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
	{
		LOG(0, 0, 0, "Error getting eth0 hardware address for GARP: %s\n", strerror(errno));
		close(s);
		return;
	}
	memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6*sizeof(char));
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
	{
		LOG(0, 0, 0, "Error getting eth0 interface index for GARP: %s\n", strerror(errno));
		close(s);
		return;
	}
	close(s);

	sendarp(ifr.ifr_ifindex, mac, config->iftun_address);
}

// rcv pppoe data from slave
void pppoe_process_forward(uint8_t *pack, int size, in_addr_t addr)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;

	if (ethhdr->h_proto == htons(ETH_P_PPP_DISC))
		process_pppoe_disc(pack, size);
	else if (ethhdr->h_proto == htons(ETH_P_PPP_SES))
		process_pppoe_sess(pack, size);
	else
		LOG(0, 0, 0, "pppoe_process_forward: I got a C_PPPOE_FORWARD from %s, but not a PPPOE data?\n", fmtaddr(addr, 0));
}
