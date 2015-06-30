// L2TP Network Server
// Adrian Kennard 2002
// Copyright (c) 2003, 2004, 2005, 2006 Optus Internet Engineering
// Copyright (c) 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd) - GPL licenced
// vim: sw=8 ts=8

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#define SYSLOG_NAMES
#include <stdio.h>
#include <syslog.h>
#include <malloc.h>
#include <math.h>
#include <net/route.h>
#include <sys/mman.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <net/if.h>
#include <stddef.h>
#include <time.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <libcli.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "md5.h"
#include "dhcp6.h"
#include "l2tpns.h"
#include "cluster.h"
#include "plugin.h"
#include "ll.h"
#include "constants.h"
#include "control.h"
#include "util.h"
#include "tbf.h"

#ifdef BGP
#include "bgp.h"
#endif

#include "l2tplac.h"
#include "pppoe.h"
#include "dhcp6.h"

char * Vendor_name = "Linux L2TPNS";
uint32_t call_serial_number = 0;

// Globals
configt *config = NULL;		// all configuration
int nlfd = -1;			// netlink socket
int tunfd = -1;			// tun interface file handle. (network device)
int udpfd[MAX_UDPFD + 1] = INIT_TABUDPFD;		// array UDP file handle + 1 for lac udp
int udplacfd = -1;		// UDP LAC file handle
int controlfd = -1;		// Control signal handle
int clifd = -1;			// Socket listening for CLI connections.
int daefd = -1;			// Socket listening for DAE connections.
int snoopfd = -1;		// UDP file handle for sending out intercept data
int *radfds = NULL;		// RADIUS requests file handles
int rand_fd = -1;		// Random data source
int cluster_sockfd = -1;	// Intra-cluster communications socket.
int epollfd = -1;		// event polling
time_t basetime = 0;		// base clock
char hostname[MAXHOSTNAME] = "";	// us.
static int tunidx;		// ifr_ifindex of tun device
int nlseqnum = 0;		// netlink sequence number
int min_initok_nlseqnum = 0;	// minimun seq number for messages after init is ok
static int syslog_log = 0;	// are we logging to syslog
static FILE *log_stream = 0;	// file handle for direct logging (i.e. direct into file, not via syslog).
uint32_t last_id = 0;		// Unique ID for radius accounting
// Guest change
char guest_users[10][32];       // Array of guest users
int guest_accounts_num = 0;     // Number of guest users

// calculated from config->l2tp_mtu
uint16_t MRU = 0;		// PPP MRU
uint16_t MSS = 0;		// TCP MSS

struct cli_session_actions *cli_session_actions = NULL;	// Pending session changes requested by CLI
struct cli_tunnel_actions *cli_tunnel_actions = NULL;	// Pending tunnel changes required by CLI

union iphash {
	sessionidt sess;
	union iphash *idx;
} ip_hash[256];			// Mapping from IP address to session structures.

struct ipv6radix {
	sessionidt sess;
	struct ipv6radix *branch;
} ipv6_hash[16];		// Mapping from IPv6 address to session structures.

// Traffic counters.
static uint32_t udp_rx = 0, udp_rx_pkt = 0, udp_tx = 0;
static uint32_t eth_rx = 0, eth_rx_pkt = 0;
uint32_t eth_tx = 0;

time_t time_now = 0;			// Current time in seconds since epoch.
uint64_t time_now_ms = 0;		// Current time in milliseconds since epoch.
static char time_now_string[64] = {0};	// Current time as a string.
static int time_changed = 0;		// time_now changed
char main_quit = 0;			// True if we're in the process of exiting.
static char main_reload = 0;		// Re-load pending
linked_list *loaded_plugins;
linked_list *plugins[MAX_PLUGIN_TYPES];

#define membersize(STRUCT, MEMBER) sizeof(((STRUCT *)0)->MEMBER)
#define CONFIG(NAME, MEMBER, TYPE) { NAME, offsetof(configt, MEMBER), membersize(configt, MEMBER), TYPE }

config_descriptt config_values[] = {
	CONFIG("debug", debug, INT),
	CONFIG("log_file", log_filename, STRING),
	CONFIG("pid_file", pid_file, STRING),
	CONFIG("random_device", random_device, STRING),
	CONFIG("l2tp_secret", l2tp_secret, STRING),
	CONFIG("l2tp_mtu", l2tp_mtu, INT),
	CONFIG("ppp_restart_time", ppp_restart_time, INT),
	CONFIG("ppp_max_configure", ppp_max_configure, INT),
	CONFIG("ppp_max_failure", ppp_max_failure, INT),
	CONFIG("primary_dns", default_dns1, IPv4),
	CONFIG("secondary_dns", default_dns2, IPv4),
	CONFIG("primary_radius", radiusserver[0], IPv4),
	CONFIG("secondary_radius", radiusserver[1], IPv4),
	CONFIG("primary_radius_port", radiusport[0], SHORT),
	CONFIG("secondary_radius_port", radiusport[1], SHORT),
	CONFIG("radius_accounting", radius_accounting, BOOL),
	CONFIG("radius_interim", radius_interim, INT),
	CONFIG("radius_secret", radiussecret, STRING),
	CONFIG("radius_authtypes", radius_authtypes_s, STRING),
	CONFIG("radius_dae_port", radius_dae_port, SHORT),
	CONFIG("radius_bind_min", radius_bind_min, SHORT),
	CONFIG("radius_bind_max", radius_bind_max, SHORT),
	CONFIG("allow_duplicate_users", allow_duplicate_users, BOOL),
	CONFIG("kill_timedout_sessions", kill_timedout_sessions, BOOL),
	CONFIG("guest_account", guest_user, STRING),
	CONFIG("bind_address", bind_address, IPv4),
	CONFIG("peer_address", peer_address, IPv4),
	CONFIG("send_garp", send_garp, BOOL),
	CONFIG("throttle_speed", rl_rate, UNSIGNED_LONG),
	CONFIG("throttle_buckets", num_tbfs, INT),
	CONFIG("accounting_dir", accounting_dir, STRING),
	CONFIG("setuid", target_uid, INT),
	CONFIG("account_all_origin", account_all_origin, BOOL),
	CONFIG("dump_speed", dump_speed, BOOL),
	CONFIG("multi_read_count", multi_read_count, INT),
	CONFIG("scheduler_fifo", scheduler_fifo, BOOL),
	CONFIG("lock_pages", lock_pages, BOOL),
	CONFIG("icmp_rate", icmp_rate, INT),
	CONFIG("packet_limit", max_packets, INT),
	CONFIG("cluster_address", cluster_address, IPv4),
	CONFIG("cluster_interface", cluster_interface, STRING),
	CONFIG("cluster_mcast_ttl", cluster_mcast_ttl, INT),
	CONFIG("cluster_hb_interval", cluster_hb_interval, INT),
	CONFIG("cluster_hb_timeout", cluster_hb_timeout, INT),
 	CONFIG("cluster_master_min_adv", cluster_master_min_adv, INT),
	CONFIG("ipv6_prefix", ipv6_prefix, IPv6),
	CONFIG("append_realm", append_realm, STRING),
        CONFIG("gardens", gardens, STRING),
        CONFIG("max_sessions",max_sessions,INT),
	CONFIG("cli_bind_address", cli_bind_address, IPv4),
	CONFIG("hostname", hostname, STRING),
#ifdef BGP
	CONFIG("nexthop_address", nexthop_address, IPv4),
	CONFIG("nexthop6_address", nexthop6_address, IPv6),
#endif
	CONFIG("echo_timeout", echo_timeout, INT),
	CONFIG("idle_echo_timeout", idle_echo_timeout, INT),
	CONFIG("iftun_address", iftun_address, IPv4),
	CONFIG("tundevicename", tundevicename, STRING),
	CONFIG("disable_lac_func", disable_lac_func, BOOL),
	CONFIG("auth_tunnel_change_addr_src", auth_tunnel_change_addr_src, BOOL),
	CONFIG("bind_address_remotelns", bind_address_remotelns, IPv4),
	CONFIG("bind_portremotelns", bind_portremotelns, SHORT),
	CONFIG("pppoe_if_to_bind", pppoe_if_to_bind, STRING),
	CONFIG("pppoe_service_name", pppoe_service_name, STRING),
	CONFIG("pppoe_ac_name", pppoe_ac_name, STRING),
	CONFIG("disable_sending_hello", disable_sending_hello, BOOL),
	CONFIG("disable_no_spoof", disable_no_spoof, BOOL),
	CONFIG("bind_multi_address", bind_multi_address, STRING),
	CONFIG("pppoe_only_equal_svc_name", pppoe_only_equal_svc_name, BOOL),
	CONFIG("multi_hostname", multi_hostname, STRING),
	CONFIG("no_throttle_local_IP", no_throttle_local_IP, BOOL),
	CONFIG("dhcp6_preferred_lifetime", dhcp6_preferred_lifetime, INT),
	CONFIG("dhcp6_valid_lifetime", dhcp6_valid_lifetime, INT),
	CONFIG("dhcp6_server_duid", dhcp6_server_duid, INT),
	CONFIG("dns6_lifetime", dns6_lifetime, INT),
	CONFIG("primary_ipv6_dns", default_ipv6_dns1, IPv6),
	CONFIG("secondary_ipv6_dns", default_ipv6_dns2, IPv6),
	CONFIG("default_ipv6_domain_list", default_ipv6_domain_list, STRING),
	{ NULL, 0, 0, 0 }
};

static char *plugin_functions[] = {
	NULL,
	"plugin_pre_auth",
	"plugin_post_auth",
	"plugin_timer",
	"plugin_new_session",
	"plugin_kill_session",
	"plugin_control",
	"plugin_radius_response",
	"plugin_radius_reset",
	"plugin_radius_account",
	"plugin_become_master",
	"plugin_new_session_master",
};

#define max_plugin_functions (sizeof(plugin_functions) / sizeof(char *))

// Counters for shutdown sessions
static sessiont shut_acct[8192];
static sessionidt shut_acct_n = 0;

tunnelt *tunnel = NULL;			// Array of tunnel structures.
bundlet *bundle = NULL;			// Array of bundle structures.
fragmentationt *frag = NULL;		// Array of fragmentation structures.
sessiont *session = NULL;		// Array of session structures.
sessionlocalt *sess_local = NULL;	// Array of local per-session counters.
radiust *radius = NULL;			// Array of radius structures.

ippoolt *ip_address_pool[MAX_POOL_COUNT];	// Array of dynamic IP addresses.
static uint32_t ip_pool_size[MAX_POOL_COUNT];	// Size of the pool of addresses used for dynamic address allocation.

ip_filtert *ip_filters = NULL;		// Array of named filters.
static controlt *controlfree = 0;
struct Tstats *_statistics = NULL;
#ifdef RINGBUFFER
struct Tringbuffer *ringbuffer = NULL;
#endif

static ssize_t netlink_send(struct nlmsghdr *nh);
static void netlink_addattr(struct nlmsghdr *nh, int type, const void *data, int alen);
static void cache_ipmap(in_addr_t ip, sessionidt s);
static void uncache_ipmap(in_addr_t ip);
static void cache_ipv6map(struct in6_addr ip, int prefixlen, sessionidt s);
static void free_ip_address(sessionidt s);
static void dump_acct_info(int all);
static void sighup_handler(int sig);
static void shutdown_handler(int sig);
static void sigchild_handler(int sig);
static void build_chap_response(uint8_t *challenge, uint8_t id, uint16_t challenge_length, uint8_t **challenge_response);
static void update_config(void);
static void read_config_file(void);
static void initplugins(void);
static int add_plugin(char *plugin_name);
static int remove_plugin(char *plugin_name);
static void plugins_done(void);
static void processcontrol(uint8_t *buf, int len, struct sockaddr_in *addr, int alen, struct in_addr *local);
static tunnelidt new_tunnel(void);
static void unhide_value(uint8_t *value, size_t len, uint16_t type, uint8_t *vector, size_t vec_len);
static void malloc_pool(uint16_t x);
static void bundleclear(bundleidt b);
static void *getconfig(char *key, enum config_typet type);

// on slaves, alow BGP to withdraw cleanly before exiting
#define QUIT_DELAY	5

// quit actions (master)
#define QUIT_FAILOVER	1 // SIGTERM: exit when all control messages have been acked (for cluster failover)
#define QUIT_SHUTDOWN	2 // SIGQUIT: shutdown sessions/tunnels, reject new connections

// return internal time (10ths since process startup), set f if given
// as a side-effect sets time_now, and time_changed
static clockt now(double *f)
{
	struct timeval t;
	gettimeofday(&t, 0);
	if (f) *f = t.tv_sec + t.tv_usec / 1000000.0;
	if (t.tv_sec != time_now)
	{
	    time_now = t.tv_sec;
	    time_changed++;
	}

	// Time in milliseconds
	// TODO FOR MLPPP DEV
	//time_now_ms = (t.tv_sec * 1000) + (t.tv_usec/1000);

	return (t.tv_sec - basetime) * 10 + t.tv_usec / 100000 + 1;
}

// work out a retry time based on try number
// This is a straight bounded exponential backoff.
// Maximum re-try time is 32 seconds. (2^5).
clockt backoff(uint8_t try)
{
	if (try > 5) try = 5;                  // max backoff
	return now(NULL) + 10 * (1 << try);
}


//
// Log a debug message.  Typically called via the LOG macro
//
void _log(int level, sessionidt s, tunnelidt t, const char *format, ...)
{
	static char message[65536] = {0};
	va_list ap;

#ifdef RINGBUFFER
	if (ringbuffer)
	{
		if (++ringbuffer->tail >= RINGBUFFER_SIZE)
			ringbuffer->tail = 0;
		if (ringbuffer->tail == ringbuffer->head)
			if (++ringbuffer->head >= RINGBUFFER_SIZE)
				ringbuffer->head = 0;

		ringbuffer->buffer[ringbuffer->tail].level = level;
		ringbuffer->buffer[ringbuffer->tail].session = s;
		ringbuffer->buffer[ringbuffer->tail].tunnel = t;
		va_start(ap, format);
		vsnprintf(ringbuffer->buffer[ringbuffer->tail].message, MAX_LOG_LENGTH, format, ap);
		va_end(ap);
	}
#endif

	if (config->debug < level) return;

	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);

	if (log_stream)
		fprintf(log_stream, "%s %02d/%02d %s", time_now_string, t, s, message);
	else if (syslog_log)
		syslog(level + 2, "%02d/%02d %s", t, s, message); // We don't need LOG_EMERG or LOG_ALERT

	va_end(ap);
}

void _log_hex(int level, const char *title, const uint8_t *data, int maxsize)
{
	int i, j;
	const uint8_t *d = data;

	if (config->debug < level) return;

	// No support for _log_hex to syslog
	if (log_stream)
	{
		_log(level, 0, 0, "%s (%d bytes):\n", title, maxsize);
		setvbuf(log_stream, NULL, _IOFBF, 16384);

		for (i = 0; i < maxsize; )
		{
			fprintf(log_stream, "%4X: ", i);
			for (j = i; j < maxsize && j < (i + 16); j++)
			{
				fprintf(log_stream, "%02X ", d[j]);
				if (j == i + 7)
					fputs(": ", log_stream);
			}

			for (; j < i + 16; j++)
			{
				fputs("   ", log_stream);
				if (j == i + 7)
					fputs(": ", log_stream);
			}

			fputs("  ", log_stream);
			for (j = i; j < maxsize && j < (i + 16); j++)
			{
				if (d[j] >= 0x20 && d[j] < 0x7f && d[j] != 0x20)
					fputc(d[j], log_stream);
				else
					fputc('.', log_stream);

				if (j == i + 7)
					fputs("  ", log_stream);
			}

			i = j;
			fputs("\n", log_stream);
		}

		fflush(log_stream);
		setbuf(log_stream, NULL);
	}
}

// update a counter, accumulating 2^32 wraps
void increment_counter(uint32_t *counter, uint32_t *wrap, uint32_t delta)
{
	uint32_t new = *counter + delta;
	if (new < *counter)
		(*wrap)++;

	*counter = new;
}

// initialise the random generator
static void initrandom(char *source)
{
	static char path[sizeof(config->random_device)] = "*undefined*";

	// reinitialise only if we are forced to do so or if the config has changed
	if (source && !strncmp(path, source, sizeof(path)))
		return;

	// close previous source, if any
	if (rand_fd >= 0)
		close(rand_fd);

	rand_fd = -1;

	if (source)
	{
		// register changes
		snprintf(path, sizeof(path), "%s", source);

		if (*path == '/')
		{
			rand_fd = open(path, O_RDONLY|O_NONBLOCK);
			if (rand_fd < 0)
				LOG(0, 0, 0, "Error opening the random device %s: %s\n",
					path, strerror(errno));
		}
	}
}

// fill buffer with random data
void random_data(uint8_t *buf, int len)
{
	int n = 0;

	CSTAT(random_data);
	if (rand_fd >= 0)
	{
		n = read(rand_fd, buf, len);
		if (n >= len) return;
		if (n < 0)
		{
			if (errno != EAGAIN)
			{
				LOG(0, 0, 0, "Error reading from random source: %s\n",
					strerror(errno));

				// fall back to rand()
				initrandom(NULL);
			}

			n = 0;
		}
	}

	// append missing data
	while (n < len)
		// not using the low order bits from the prng stream
		buf[n++] = (rand() >> 4) & 0xff;
}

// Add a route
//
// This adds it to the routing table, advertises it
// via BGP if enabled, and stuffs it into the
// 'sessionbyip' cache.
//
// 'ip' and 'mask' must be in _host_ order.
//
/*
static void oldioctlrouteset (
sessionidt s, in_addr_t ip, in_addr_t mask, in_addr_t gw, int add)
{
	struct rtentry r;
	int i;

	memset(&r, 0, sizeof(r));
	r.rt_dev = config->tundevicename;
	r.rt_dst.sa_family = AF_INET;
	*(uint32_t *) & (((struct sockaddr_in *) &r.rt_dst)->sin_addr.s_addr) = htonl(ip);
	r.rt_gateway.sa_family = AF_INET;
	*(uint32_t *) & (((struct sockaddr_in *) &r.rt_gateway)->sin_addr.s_addr) = htonl(gw);
	r.rt_genmask.sa_family = AF_INET;
	*(uint32_t *) & (((struct sockaddr_in *) &r.rt_genmask)->sin_addr.s_addr) = htonl(mask);
	r.rt_flags = (RTF_UP | RTF_STATIC);
	if (gw)
		r.rt_flags |= RTF_GATEWAY;
	else if (mask == 0xffffffff)
		r.rt_flags |= RTF_HOST;

	LOG(1, s, 0, "Route %s %s/%s%s%s\n", add ? "add" : "del",
	    fmtaddr(htonl(ip), 0), fmtaddr(htonl(mask), 1),
	    gw ? " via" : "", gw ? fmtaddr(htonl(gw), 2) : "");

	if (ioctl(ifrfd, add ? SIOCADDRT : SIOCDELRT, (void *) &r) < 0)
		LOG(0, 0, 0, "routeset() error in ioctl: %s\n", strerror(errno));
}
*/

static void routeset(sessionidt s, in_addr_t ip, int prefixlen, in_addr_t gw, int add)
{
	struct {
		struct nlmsghdr nh;
		struct rtmsg rt;
		char buf[32];
	} req;
	int i;
	in_addr_t n_ip;

	if (!prefixlen) prefixlen = 32;

	ip &= 0xffffffff << (32 - prefixlen);;	// Force the ip to be the first one in the route.

	memset(&req, 0, sizeof(req));

	if (add)
	{
		req.nh.nlmsg_type = RTM_NEWROUTE;
		req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
	}
	else
	{
		req.nh.nlmsg_type = RTM_DELROUTE;
		req.nh.nlmsg_flags = NLM_F_REQUEST;
	}

	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rt));

	req.rt.rtm_family = AF_INET;
	req.rt.rtm_dst_len = prefixlen;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_protocol = 42;
	req.rt.rtm_scope = RT_SCOPE_LINK;
	req.rt.rtm_type = RTN_UNICAST;

	netlink_addattr(&req.nh, RTA_OIF, &tunidx, sizeof(int));
	n_ip = htonl(ip);
	netlink_addattr(&req.nh, RTA_DST, &n_ip, sizeof(n_ip));
	if (gw)
	{
		n_ip = htonl(gw);
		netlink_addattr(&req.nh, RTA_GATEWAY, &n_ip, sizeof(n_ip));
	}

	LOG(1, s, session[s].tunnel, "Route %s %s/%d%s%s\n", add ? "add" : "del",
	    fmtaddr(htonl(ip), 0), prefixlen,
	    gw ? " via" : "", gw ? fmtaddr(htonl(gw), 2) : "");

	if (netlink_send(&req.nh) < 0) {
		LOG(0, 0, 0, "netlink failed for routeset(); need ioctl(): %s\n", strerror(errno));
		//oldioctlrouteset(s,ip,gw,add);
	}

#ifdef BGP
	if (add)
		bgp_add_route(htonl(ip), prefixlen);
	else
		bgp_del_route(htonl(ip), prefixlen);
#endif /* BGP */

		// Add/Remove the IPs to the 'sessionbyip' cache.
		// Note that we add the zero address in the case of
		// a network route. Roll on CIDR.

		// Note that 's == 0' implies this is the address pool.
		// We still cache it here, because it will pre-fill
		// the malloc'ed tree.

	if (s)
	{
		if (!add)	// Are we deleting a route?
			s = 0;	// Caching the session as '0' is the same as uncaching.

		for (i = ip; i < ip+(1<<(32-prefixlen)) ; ++i)
			cache_ipmap(i, s);
	}
}

void route6set(sessionidt s, struct in6_addr ip, int prefixlen, int add)
{
	struct {
		struct nlmsghdr nh;
		struct rtmsg rt;
		char buf[64];
	} req;
	int metric;
	char ipv6addr[INET6_ADDRSTRLEN];

	if (!config->ipv6_prefix.s6_addr[0])
	{
		LOG(0, 0, 0, "Asked to set IPv6 route, but IPv6 not setup.\n");
		return;
	}

	memset(&req, 0, sizeof(req));

	if (add)
	{
		req.nh.nlmsg_type = RTM_NEWROUTE;
		req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
	}
	else
	{
		req.nh.nlmsg_type = RTM_DELROUTE;
		req.nh.nlmsg_flags = NLM_F_REQUEST;
	}

	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rt));

	req.rt.rtm_family = AF_INET6;
	req.rt.rtm_dst_len = prefixlen;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_protocol = 42;
	req.rt.rtm_scope = RT_SCOPE_LINK;
	req.rt.rtm_type = RTN_UNICAST;

	netlink_addattr(&req.nh, RTA_OIF, &tunidx, sizeof(int));
	netlink_addattr(&req.nh, RTA_DST, &ip, sizeof(ip));
	metric = 1;
	netlink_addattr(&req.nh, RTA_METRICS, &metric, sizeof(metric));

	LOG(1, s, session[s].tunnel, "Route %s %s/%d\n",
	    add ? "add" : "del",
	    inet_ntop(AF_INET6, &ip, ipv6addr, INET6_ADDRSTRLEN),
	    prefixlen);

	if (netlink_send(&req.nh) < 0)
		LOG(0, 0, 0, "route6set() error in sending netlink message: %s\n", strerror(errno));

#ifdef BGP
	if (add)
		bgp_add_route6(ip, prefixlen);
	else
		bgp_del_route6(ip, prefixlen);
#endif /* BGP */

	if (s)
	{
		if (!add)	// Are we deleting a route?
			s = 0;	// Caching the session as '0' is the same as uncaching.

		cache_ipv6map(ip, prefixlen, s);
	}
	
	return;
}

//
// Set up netlink socket
static void initnetlink(void)
{
	struct sockaddr_nl nladdr;

	nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlfd < 0)
	{
		LOG(0, 0, 0, "Can't create netlink socket: %s\n", strerror(errno));
		exit(1);
	}

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = getpid();

	if (bind(nlfd, (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0)
	{
		LOG(0, 0, 0, "Can't bind netlink socket: %s\n", strerror(errno));
		exit(1);
	}
}

static ssize_t netlink_send(struct nlmsghdr *nh)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;

	nh->nlmsg_pid = getpid();
	nh->nlmsg_seq = ++nlseqnum;

	// set kernel address
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	iov = (struct iovec){ (void *)nh, nh->nlmsg_len };
	msg = (struct msghdr){ (void *)&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

	return sendmsg(nlfd, &msg, 0);
}

static ssize_t netlink_recv(void *buf, ssize_t len)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;

	// set kernel address
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	iov = (struct iovec){ buf, len };
	msg = (struct msghdr){ (void *)&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

	return recvmsg(nlfd, &msg, 0);
}

/* adapted from iproute2 */
static void netlink_addattr(struct nlmsghdr *nh, int type, const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	rta = (struct rtattr *)(((void *)nh) + NLMSG_ALIGN(nh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(len);
}

// messages corresponding to different phases seq number
static char *tun_nl_phase_msg[] = {
	"initialized",
	"getting tun interface index",
	"setting tun interface parameters",
	"setting tun IPv4 address",
	"setting tun LL IPv6 address",
	"setting tun global IPv6 address",
};

//
// Set up TUN interface
static void inittun(void)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;

	tunfd = open(TUNDEVICE, O_RDWR);
	if (tunfd < 0)
	{                          // fatal
		LOG(0, 0, 0, "Can't open %s: %s\n", TUNDEVICE, strerror(errno));
		exit(1);
	}
	{
		int flags = fcntl(tunfd, F_GETFL, 0);
		fcntl(tunfd, F_SETFL, flags | O_NONBLOCK);
	}

   if (*config->tundevicename)
		strncpy(ifr.ifr_name, config->tundevicename, IFNAMSIZ);

	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0)
	{
		LOG(0, 0, 0, "Can't set tun interface: %s\n", strerror(errno));
		exit(1);
	}
	assert(strlen(ifr.ifr_name) < sizeof(config->tundevicename) - 1);
	strncpy(config->tundevicename, ifr.ifr_name, sizeof(config->tundevicename));

	tunidx = if_nametoindex(config->tundevicename);
	if (tunidx == 0)
	{
		LOG(0, 0, 0, "Can't get tun interface index\n");
		exit(1);
	}

	{
		struct {
			// interface setting
			struct nlmsghdr nh;
			union {
				struct ifinfomsg ifinfo;
				struct ifaddrmsg ifaddr;
			} ifmsg;
			char rtdata[32]; // 32 should be enough
		} req;
		uint32_t txqlen, mtu;
		in_addr_t ip;

		memset(&req, 0, sizeof(req));

		req.nh.nlmsg_type = RTM_NEWLINK;
		req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_MULTI;
		req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifmsg.ifinfo));

		req.ifmsg.ifinfo.ifi_family = AF_UNSPEC;
		req.ifmsg.ifinfo.ifi_index = tunidx;
		req.ifmsg.ifinfo.ifi_flags |= IFF_UP; // set interface up
		req.ifmsg.ifinfo.ifi_change = IFF_UP; // only change this flag

		/* Bump up the qlen to deal with bursts from the network */
		txqlen = 1000;
		netlink_addattr(&req.nh, IFLA_TXQLEN, &txqlen, sizeof(txqlen));
		/* set MTU to modem MRU */
		mtu = MRU;
		netlink_addattr(&req.nh, IFLA_MTU, &mtu, sizeof(mtu));

		if (netlink_send(&req.nh) < 0)
			goto senderror;

		memset(&req, 0, sizeof(req));

		req.nh.nlmsg_type = RTM_NEWADDR;
		req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_MULTI;
		req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifmsg.ifaddr));

		req.ifmsg.ifaddr.ifa_family = AF_INET;
		req.ifmsg.ifaddr.ifa_prefixlen = 32;
		req.ifmsg.ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
		req.ifmsg.ifaddr.ifa_index = tunidx;

		if (config->nbmultiaddress > 1)
		{
			int i;
			for (i = 0; i < config->nbmultiaddress ; i++)
			{
				ip = config->iftun_n_address[i];
				netlink_addattr(&req.nh, IFA_LOCAL, &ip, sizeof(ip));
				if (netlink_send(&req.nh) < 0)
					goto senderror;
			}
		}
		else
		{
			if (config->iftun_address)
				ip = config->iftun_address;
			else
				ip = 0x01010101; // 1.1.1.1
			netlink_addattr(&req.nh, IFA_LOCAL, &ip, sizeof(ip));

			if (netlink_send(&req.nh) < 0)
				goto senderror;
		}



		// Only setup IPv6 on the tun device if we have a configured prefix
		if (config->ipv6_prefix.s6_addr[0]) {
			struct in6_addr ip6;

			memset(&req, 0, sizeof(req));

			req.nh.nlmsg_type = RTM_NEWADDR;
			req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_MULTI;
			req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifmsg.ifaddr));

			req.ifmsg.ifaddr.ifa_family = AF_INET6;
			req.ifmsg.ifaddr.ifa_prefixlen = 64;
			req.ifmsg.ifaddr.ifa_scope = RT_SCOPE_LINK;
			req.ifmsg.ifaddr.ifa_index = tunidx;

			// Link local address is FE80::1
			memset(&ip6, 0, sizeof(ip6));
			ip6.s6_addr[0] = 0xFE;
			ip6.s6_addr[1] = 0x80;
			ip6.s6_addr[15] = 1;
			netlink_addattr(&req.nh, IFA_LOCAL, &ip6, sizeof(ip6));

			if (netlink_send(&req.nh) < 0)
				goto senderror;

			memset(&req, 0, sizeof(req));

			req.nh.nlmsg_type = RTM_NEWADDR;
			req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_MULTI;
			req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifmsg.ifaddr));

			req.ifmsg.ifaddr.ifa_family = AF_INET6;
			req.ifmsg.ifaddr.ifa_prefixlen = 64;
			req.ifmsg.ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
			req.ifmsg.ifaddr.ifa_index = tunidx;

			// Global address is prefix::1
			ip6 = config->ipv6_prefix;
			ip6.s6_addr[15] = 1;
			netlink_addattr(&req.nh, IFA_LOCAL, &ip6, sizeof(ip6));

			if (netlink_send(&req.nh) < 0)
				goto senderror;
		}

		memset(&req, 0, sizeof(req));

		req.nh.nlmsg_type = NLMSG_DONE;
		req.nh.nlmsg_len = NLMSG_LENGTH(0);

		if (netlink_send(&req.nh) < 0)
			goto senderror;

		// if we get an error for seqnum < min_initok_nlseqnum,
		// we must exit as initialization went wrong
		if (config->ipv6_prefix.s6_addr[0])
			min_initok_nlseqnum = 5 + 1; // idx + if + addr + 2*addr6
		else
			min_initok_nlseqnum = 3 + 1; // idx + if + addr
	}

	return;

senderror:
	LOG(0, 0, 0, "Error while setting up tun device: %s\n", strerror(errno));
	exit(1);
}

// set up LAC UDP ports
static void initlacudp(void)
{
	int on = 1;
	struct sockaddr_in addr;

	// Tunnel to Remote LNS
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(config->bind_portremotelns);
	addr.sin_addr.s_addr = config->bind_address_remotelns;
	udplacfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt(udplacfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	{
		int flags = fcntl(udplacfd, F_GETFL, 0);
		fcntl(udplacfd, F_SETFL, flags | O_NONBLOCK);
	}
	if (bind(udplacfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "Error in UDP REMOTE LNS bind: %s\n", strerror(errno));
		exit(1);
	}
}

// set up control ports
static void initcontrol(void)
{
	int on = 1;
	struct sockaddr_in addr;

	// Control
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(NSCTL_PORT);
	controlfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	setsockopt(controlfd, SOL_IP, IP_PKTINFO, &on, sizeof(on)); // recvfromto
	if (bind(controlfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "Error in control bind: %s\n", strerror(errno));
		exit(1);
	}
}

// set up Dynamic Authorization Extensions to RADIUS port
static void initdae(void)
{
	int on = 1;
	struct sockaddr_in addr;

	// Dynamic Authorization Extensions to RADIUS
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(config->radius_dae_port);
	daefd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt(daefd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	setsockopt(daefd, SOL_IP, IP_PKTINFO, &on, sizeof(on)); // recvfromto
	if (bind(daefd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "Error in DAE bind: %s\n", strerror(errno));
		exit(1);
	}
}

// set up UDP ports
static void initudp(int * pudpfd, in_addr_t ip_bind)
{
	int on = 1;
	struct sockaddr_in addr;

	// Tunnel
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(L2TPPORT);
	addr.sin_addr.s_addr = ip_bind;
	(*pudpfd) = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt((*pudpfd), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	{
		int flags = fcntl((*pudpfd), F_GETFL, 0);
		fcntl((*pudpfd), F_SETFL, flags | O_NONBLOCK);
	}
	if (bind((*pudpfd), (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "Error in UDP bind: %s\n", strerror(errno));
		exit(1);
	}
}

//
// Find session by IP, < 1 for not found
//
// Confusingly enough, this 'ip' must be
// in _network_ order. This being the common
// case when looking it up from IP packet headers.
//
// We actually use this cache for two things.
// #1. For used IP addresses, this maps to the
// session ID that it's used by.
// #2. For un-used IP addresses, this maps to the
// index into the pool table that contains that
// IP address.
//

static sessionidt lookup_ipmap(in_addr_t ip)
{
	uint8_t *a = (uint8_t *) &ip;
	union iphash *h = ip_hash;

	if (!(h = h[*a++].idx)) return 0;
	if (!(h = h[*a++].idx)) return 0;
	if (!(h = h[*a++].idx)) return 0;

	return h[*a].sess;
}

static sessionidt lookup_ipv6map(struct in6_addr ip)
{
	struct ipv6radix *curnode;
	int i;
	int s;
	char ipv6addr[INET6_ADDRSTRLEN];

	curnode = &ipv6_hash[((ip.s6_addr[0]) & 0xF0)>>4];
	i = 1;
	s = curnode->sess;

	while (s == 0 && i < 32 && curnode->branch != NULL)
	{
		if (i & 1)
			curnode = &curnode->branch[ip.s6_addr[i>>1] & 0x0F];
		else
			curnode = &curnode->branch[(ip.s6_addr[i>>1] & 0xF0)>>4];

		s = curnode->sess;
		i++;
	}

	LOG(4, s, session[s].tunnel, "Looking up address %s and got %d\n",
			inet_ntop(AF_INET6, &ip, ipv6addr,
			INET6_ADDRSTRLEN),
			s);

	return s;
}

sessionidt sessionbyip(in_addr_t ip)
{
	sessionidt s = lookup_ipmap(ip);
	CSTAT(sessionbyip);

	if (s > 0 && s < MAXSESSION && session[s].opened)
		return s;

	return 0;
}

sessionidt sessionbyipv6(struct in6_addr ip)
{
	sessionidt s;
	CSTAT(sessionbyipv6);

	if (!memcmp(&config->ipv6_prefix, &ip, 8) ||
		(ip.s6_addr[0] == 0xFE &&
		 ip.s6_addr[1] == 0x80 &&
		 ip.s6_addr16[1] == 0 &&
		 ip.s6_addr16[2] == 0 &&
		 ip.s6_addr16[3] == 0))
	{
		in_addr_t *pipv4 = (in_addr_t *) &ip.s6_addr[8];
		s = lookup_ipmap(*pipv4);
	} else {
		s = lookup_ipv6map(ip);
	}

	if (s > 0 && s < MAXSESSION && session[s].opened)
		return s;

	return 0;
}

sessionidt sessionbyipv6new(struct in6_addr ip)
{
	sessionidt s;
	CSTAT(sessionbyipv6new);

	s = lookup_ipv6map(ip);

	if (s > 0 && s < MAXSESSION && session[s].opened)
		return s;

	return 0;
}

//
// Take an IP address in HOST byte order and
// add it to the sessionid by IP cache.
//
// (It's actually cached in network order)
//
static void cache_ipmap(in_addr_t ip, sessionidt s)
{
	in_addr_t nip = htonl(ip);	// MUST be in network order. I.e. MSB must in be ((char *) (&ip))[0]
	uint8_t *a = (uint8_t *) &nip;
	union iphash *h = ip_hash;
	int i;

	for (i = 0; i < 3; i++)
	{
		if (!(h[a[i]].idx || (h[a[i]].idx = calloc(256, sizeof(union iphash)))))
			return;

		h = h[a[i]].idx;
	}

	h[a[3]].sess = s;

	if (s > 0)
		LOG(4, s, session[s].tunnel, "Caching ip address %s\n", fmtaddr(nip, 0));

	else if (s == 0)
		LOG(4, 0, 0, "Un-caching ip address %s\n", fmtaddr(nip, 0));
	// else a map to an ip pool index.
}

static void uncache_ipmap(in_addr_t ip)
{
	cache_ipmap(ip, 0);	// Assign it to the NULL session.
}

static void cache_ipv6map(struct in6_addr ip, int prefixlen, sessionidt s)
{
	int i;
	int niblles;
	struct ipv6radix *curnode;
	char ipv6addr[INET6_ADDRSTRLEN];

	curnode = &ipv6_hash[((ip.s6_addr[0]) & 0xF0)>>4];

	niblles = prefixlen >> 2;
	i = 1;

	while (i < niblles)
	{
		if (curnode->branch == NULL)
		{
			if (!(curnode->branch = calloc(16, sizeof (struct ipv6radix))))
				return;
		}

		if (i & 1)
			curnode = &curnode->branch[ip.s6_addr[i>>1] & 0x0F];
		else
			curnode = &curnode->branch[(ip.s6_addr[i>>1] & 0xF0)>>4];

		i++;
	}

	curnode->sess = s;

	if (s > 0)
		LOG(4, s, session[s].tunnel, "Caching ip address %s/%d\n",
				inet_ntop(AF_INET6, &ip, ipv6addr,
				INET6_ADDRSTRLEN),
				prefixlen);
	else if (s == 0)
		LOG(4, 0, 0, "Un-caching ip address %s/%d\n",
				inet_ntop(AF_INET6, &ip, ipv6addr,
				INET6_ADDRSTRLEN),
				prefixlen);
}

//
// CLI list to dump current ipcache.
//
int cmd_show_ipcache(struct cli_def *cli, const char *command, char **argv, int argc)
{
	union iphash *d = ip_hash, *e, *f, *g;
	int i, j, k, l;
	int count = 0;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "%7s %s", "Sess#", "IP Address");

	for (i = 0; i < 256; ++i)
	{
		if (!d[i].idx)
			continue;

		e = d[i].idx;
		for (j = 0; j < 256; ++j)
		{
			if (!e[j].idx)
				continue;

			f = e[j].idx;
			for (k = 0; k < 256; ++k)
			{
				if (!f[k].idx)
					continue;

				g = f[k].idx;
				for (l = 0; l < 256; ++l)
				{
					if (!g[l].sess)
						continue;

					cli_print(cli, "%7d %d.%d.%d.%d", g[l].sess, i, j, k, l);
					++count;
				}
			}
		}
	}
	cli_print(cli, "%d entries in cache", count);
	return CLI_OK;
}

// Find session by username, 0 for not found
// walled garden users aren't authenticated, so the username is
// reasonably useless. Ignore them to avoid incorrect actions
//
// This is VERY inefficent. Don't call it often. :)
//
sessionidt sessionbyuser(char *username)
{
	int s;
	CSTAT(sessionbyuser);

	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
	{
		if (!session[s].opened)
			continue;

		if (session[s].walled_garden)
			continue;		// Skip walled garden users.

		if (!strncmp(session[s].user, username, 128))
			return s;

	}
	return 0;	// Not found.
}

void send_garp(in_addr_t ip)
{
	int s;
	struct ifreq ifr;
	uint8_t mac[6];

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		LOG(0, 0, 0, "Error creating socket for GARP: %s\n", strerror(errno));
		return;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name) - 1);
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
	sendarp(ifr.ifr_ifindex, mac, ip);
}

static sessiont *sessiontbysessionidt(sessionidt s)
{
	if (!s || s >= MAXSESSION) return NULL;
	return &session[s];
}

static sessionidt sessionidtbysessiont(sessiont *s)
{
	sessionidt val = s-session;
	if (s < session || val >= MAXSESSION) return 0;
	return val;
}

// actually send a control message for a specific tunnel
void tunnelsend(uint8_t * buf, uint16_t l, tunnelidt t)
{
	struct sockaddr_in addr;

	CSTAT(tunnelsend);

	if (!t)
	{
		LOG(0, 0, t, "tunnelsend called with 0 as tunnel id\n");
		STAT(tunnel_tx_errors);
		return;
	}

	if (t == TUNNEL_ID_PPPOE)
	{
		pppoe_sess_send(buf, l, t);
		return;
	}

	if (!tunnel[t].ip)
	{
		LOG(1, 0, t, "Error sending data out tunnel: no remote endpoint (tunnel not set up)\n");
		STAT(tunnel_tx_errors);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	*(uint32_t *) & addr.sin_addr = htonl(tunnel[t].ip);
	addr.sin_port = htons(tunnel[t].port);

	// sequence expected, if sequence in message
	if (*buf & 0x08) *(uint16_t *) (buf + ((*buf & 0x40) ? 10 : 8)) = htons(tunnel[t].nr);

	// If this is a control message, deal with retries
	if (*buf & 0x80)
	{
		tunnel[t].last = time_now; // control message sent
		tunnel[t].retry = backoff(tunnel[t].try); // when to resend
		if (tunnel[t].try)
		{
			STAT(tunnel_retries);
			LOG(3, 0, t, "Control message resend try %d\n", tunnel[t].try);
		}
	}

	if (sendto(udpfd[tunnel[t].indexudp], buf, l, 0, (void *) &addr, sizeof(addr)) < 0)
	{
		if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) 
		{
			usleep(500);
			LOG(0, ntohs((*(uint16_t *) (buf + 6))), t, "Congestion on tunnel socket: : %s (udpfd=%d, buf=%p, len=%d, dest=%s)\n",
			strerror(errno), udpfd[tunnel[t].indexudp], buf, l, inet_ntoa(addr.sin_addr));
			if (sendto(udpfd[tunnel[t].indexudp], buf, l, 0, (void *) &addr, sizeof(addr)) >= 0)
			{
				goto tunnel_sentok;
			}
		}
		LOG(0, ntohs((*(uint16_t *) (buf + 6))), t, "Error sending data out tunnel: %s (udpfd=%d, buf=%p, len=%d, dest=%s)\n",
				strerror(errno), udpfd[tunnel[t].indexudp], buf, l, inet_ntoa(addr.sin_addr));
		STAT(tunnel_tx_errors);
		return;
	}

tunnel_sentok:
	LOG_HEX(5, "Send Tunnel Data", buf, l);
	STAT(tunnel_tx_packets);
	INC_STAT(tunnel_tx_bytes, l);
}

//
// Tiny helper function to write data to
// the 'tun' device.
//
int tun_write(uint8_t * data, int size)
{
	return write(tunfd, data, size);
}

// adjust tcp mss to avoid fragmentation (called only for tcp packets with syn set)
void adjust_tcp_mss(sessionidt s, tunnelidt t, uint8_t *buf, int len, uint8_t *tcp)
{
	int d = (tcp[12] >> 4) * 4;
	uint8_t *mss = 0;
	uint8_t *opts;
	uint8_t *data;
	uint16_t orig;
	uint32_t sum;

	if ((tcp[13] & 0x3f) & ~(TCP_FLAG_SYN|TCP_FLAG_ACK)) // only want SYN and SYN,ACK
		return;

	if (tcp + d > buf + len) // short?
		return;

	opts = tcp + 20;
	data = tcp + d;

	while (opts < data)
	{
		if (*opts == 2 && opts[1] == 4) // mss option (2), length 4
		{
			mss = opts + 2;
			if (mss + 2 > data) return; // short?
			break;
		}

		if (*opts == 0) return; // end of options
		if (*opts == 1 || !opts[1]) // no op (one byte), or no length (prevent loop)
			opts++;
		else
			opts += opts[1]; // skip over option
	}

	if (!mss) return; // not found
	orig = ntohs(*(uint16_t *) mss);

	if (orig <= MSS) return; // mss OK

	LOG(5, s, t, "TCP: %s:%u -> %s:%u SYN%s: adjusted mss from %u to %u\n",
		fmtaddr(*(in_addr_t *) (buf + 12), 0), ntohs(*(uint16_t *) tcp),
		fmtaddr(*(in_addr_t *) (buf + 16), 1), ntohs(*(uint16_t *) (tcp + 2)),
		(tcp[13] & TCP_FLAG_ACK) ? ",ACK" : "", orig, MSS);

	// set mss
	*(int16_t *) mss = htons(MSS);

	// adjust checksum (see rfc1141)
	sum = orig + (~MSS & 0xffff);
	sum += ntohs(*(uint16_t *) (tcp + 16));
	sum = (sum & 0xffff) + (sum >> 16);
	*(uint16_t *) (tcp + 16) = htons(sum + (sum >> 16));
}

void processmpframe(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l, uint8_t extra)
{
	uint16_t proto;
	if (extra) {
		// Skip the four extra bytes
		p += 4;
		l -= 4;
	}

        if (*p & 1)
        {
                proto = *p++;
                l--;
        }
        else
        {
                proto = ntohs(*(uint16_t *) p);
                p += 2;
                l -= 2;
        }
        if (proto == PPPIP)
        {
                if (session[s].die)
                {
                        LOG(4, s, t, "MPPP: Session %d is closing.  Don't process PPP packets\n", s);
                        return;              // closing session, PPP not processed
                }
                session[s].last_packet = session[s].last_data = time_now;
                processipin(s, t, p, l);
        }
        else if (proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0])
        {
                if (session[s].die)
                {
                        LOG(4, s, t, "MPPP: Session %d is closing.  Don't process PPP packets\n", s);
                        return;              // closing session, PPP not processed
                }

                session[s].last_packet = session[s].last_data = time_now;
                processipv6in(s, t, p, l);
        }
	else if (proto == PPPIPCP)
        {
                session[s].last_packet = session[s].last_data = time_now;
                processipcp(s, t, p, l);
        }
        else if (proto == PPPCCP)
        {
                session[s].last_packet = session[s].last_data = time_now;
                processccp(s, t, p, l);
        }
        else
        {
                LOG(2, s, t, "MPPP: Unsupported MP protocol 0x%04X received\n",proto);
        }
}

static void update_session_out_stat(sessionidt s, sessiont *sp, int len)
{
	increment_counter(&sp->cout, &sp->cout_wrap, len); // byte count
	sp->cout_delta += len;
	sp->pout++;
	sp->last_data = time_now;

	sess_local[s].cout += len;	// To send to master..
	sess_local[s].pout++;
}

// process outgoing (to tunnel) IP
//
// (i.e. this routine writes to data[-8]).
void processipout(uint8_t *buf, int len)
{
	sessionidt s;
	sessiont *sp;
	tunnelidt t;
	in_addr_t ip, ip_src;

	uint8_t *data = buf;	// Keep a copy of the originals.
	int size = len;

	uint8_t fragbuf[MAXETHER + 20];

	CSTAT(processipout);

	if (len < MIN_IP_SIZE)
	{
		LOG(1, 0, 0, "Short IP, %d bytes\n", len);
		STAT(tun_rx_errors);
		return;
	}
	if (len >= MAXETHER)
	{
		LOG(1, 0, 0, "Oversize IP packet %d bytes\n", len);
		STAT(tun_rx_errors);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	// Got an IP header now
	if (*(uint8_t *)(buf) >> 4 != 4)
	{
		LOG(1, 0, 0, "IP: Don't understand anything except IPv4\n");
		return;
	}

	ip_src = *(uint32_t *)(buf + 12);
	ip = *(uint32_t *)(buf + 16);
	if (!(s = sessionbyip(ip)))
	{
		// Is this a packet for a session that doesn't exist?
		static int rate = 0;	// Number of ICMP packets we've sent this second.
		static int last = 0;	// Last time we reset the ICMP packet counter 'rate'.

		if (last != time_now)
		{
			last = time_now;
			rate = 0;
		}

		if (rate++ < config->icmp_rate) // Only send a max of icmp_rate per second.
		{
			LOG(4, 0, 0, "IP: Sending ICMP host unreachable to %s\n", fmtaddr(*(in_addr_t *)(buf + 12), 0));
			host_unreachable(*(in_addr_t *)(buf + 12), *(uint16_t *)(buf + 4),
				config->bind_address ? config->bind_address : my_address, buf, len);
		}
		return;
	}

	t = session[s].tunnel;
	if (len > session[s].mru || (session[s].mrru && len > session[s].mrru))
	{
		LOG(3, s, t, "Packet size more than session MRU\n");
		return;
	}

	sp = &session[s];

	// DoS prevention: enforce a maximum number of packets per 0.1s for a session
	if (config->max_packets > 0)
	{
		if (sess_local[s].last_packet_out == TIME)
		{
			int max = config->max_packets;

			// All packets for throttled sessions are handled by the
			// master, so further limit by using the throttle rate.
			// A bit of a kludge, since throttle rate is in kbps,
			// but should still be generous given our average DSL
			// packet size is 200 bytes: a limit of 28kbps equates
			// to around 180 packets per second.
			if (!config->cluster_iam_master && sp->throttle_out && sp->throttle_out < max)
				max = sp->throttle_out;

			if (++sess_local[s].packets_out > max)
			{
				sess_local[s].packets_dropped++;
				return;
			}
		}
		else
		{
			if (sess_local[s].packets_dropped)
			{
				INC_STAT(tun_rx_dropped, sess_local[s].packets_dropped);
				LOG(3, s, t, "Dropped %u/%u packets to %s for %suser %s\n",
					sess_local[s].packets_dropped, sess_local[s].packets_out,
					fmtaddr(ip, 0), sp->throttle_out ? "throttled " : "",
					sp->user);
			}

			sess_local[s].last_packet_out = TIME;
			sess_local[s].packets_out = 1;
			sess_local[s].packets_dropped = 0;
		}
	}

	// run access-list if any
	if (session[s].filter_out && !ip_filter(buf, len, session[s].filter_out - 1))
		return;

	// adjust MSS on SYN and SYN,ACK packets with options
	if ((ntohs(*(uint16_t *) (buf + 6)) & 0x1fff) == 0 && buf[9] == IPPROTO_TCP) // first tcp fragment
	{
		int ihl = (buf[0] & 0xf) * 4; // length of IP header
		if (len >= ihl + 20 && (buf[ihl + 13] & TCP_FLAG_SYN) && ((buf[ihl + 12] >> 4) > 5))
			adjust_tcp_mss(s, t, buf, len, buf + ihl);
	}

	if (sp->tbf_out)
	{
		if (!config->no_throttle_local_IP || !sessionbyip(ip_src))
		{
			// Are we throttling this session?
			if (config->cluster_iam_master)
				tbf_queue_packet(sp->tbf_out, data, size);
			else
				master_throttle_packet(sp->tbf_out, data, size);
			return;
		}
	}

	if (sp->walled_garden && !config->cluster_iam_master)
	{
		// We are walled-gardening this
		master_garden_packet(s, data, size);
		return;
	}

	if(session[s].bundle != 0 && bundle[session[s].bundle].num_of_links > 1)
	{

		if (!config->cluster_iam_master)
		{
			// The MPPP packets must be managed by the Master.
			master_forward_mppp_packet(s, data, size);
			return;
		}

		// Add on L2TP header
		sessionidt members[MAXBUNDLESES];
		bundleidt bid = session[s].bundle;
		bundlet *b = &bundle[bid];
		uint32_t num_of_links, nb_opened;
		int i;

		num_of_links = b->num_of_links;
		nb_opened = 0;
		for (i = 0;i < num_of_links;i++)
		{
			s = b->members[i];
			if (session[s].ppp.lcp == Opened)
			{
				members[nb_opened] = s;
				nb_opened++;
			}
		}

		if (nb_opened < 1)
		{
			LOG(3, s, t, "MPPP: PROCESSIPOUT ERROR, no session opened in bundle:%d\n", bid);
			return;
		}

		num_of_links = nb_opened;
		b->current_ses = (b->current_ses + 1) % num_of_links;
		s = members[b->current_ses];
		t = session[s].tunnel;
		sp = &session[s];
		LOG(4, s, t, "MPPP: (1)Session number becomes: %d\n", s);

		if (num_of_links > 1)
		{
			if(len > MINFRAGLEN)
			{
				//for rotate traffic among the member links
				uint32_t divisor = num_of_links;
				if (divisor > 2)
					divisor = divisor/2 + (divisor & 1);

				// Partition the packet to "num_of_links" fragments
				uint32_t fraglen = len / divisor;
				uint32_t last_fraglen = fraglen + len % divisor;
				uint32_t remain = len;

				// send the first packet
				uint8_t *p = makeppp(fragbuf, sizeof(fragbuf), buf, fraglen, s, t, PPPIP, 0, bid, MP_BEGIN);
				if (!p) return;
				tunnelsend(fragbuf, fraglen + (p-fragbuf), t); // send it...

				// statistics
				update_session_out_stat(s, sp, fraglen);

				remain -= fraglen;
				while (remain > last_fraglen)
				{
					b->current_ses = (b->current_ses + 1) % num_of_links;
					s = members[b->current_ses];
					t = session[s].tunnel;
					sp = &session[s];
					LOG(4, s, t, "MPPP: (2)Session number becomes: %d\n", s);
					p = makeppp(fragbuf, sizeof(fragbuf), buf+(len - remain), fraglen, s, t, PPPIP, 0, bid, 0);
					if (!p) return;
					tunnelsend(fragbuf, fraglen + (p-fragbuf), t); // send it...
					update_session_out_stat(s, sp, fraglen);
					remain -= fraglen;
				}
				// send the last fragment
				b->current_ses = (b->current_ses + 1) % num_of_links;
				s = members[b->current_ses];
				t = session[s].tunnel;
				sp = &session[s];
				LOG(4, s, t, "MPPP: (2)Session number becomes: %d\n", s);
				p = makeppp(fragbuf, sizeof(fragbuf), buf+(len - remain), remain, s, t, PPPIP, 0, bid, MP_END);
				if (!p) return;
				tunnelsend(fragbuf, remain + (p-fragbuf), t); // send it...
				update_session_out_stat(s, sp, remain);
				if (remain != last_fraglen)
					LOG(3, s, t, "PROCESSIPOUT ERROR REMAIN != LAST_FRAGLEN, %d != %d\n", remain, last_fraglen);
			}
			else
			{
				// Send it as one frame
				uint8_t *p = makeppp(fragbuf, sizeof(fragbuf), buf, len, s, t, PPPIP, 0, bid, MP_BOTH_BITS);
				if (!p) return;
				tunnelsend(fragbuf, len + (p-fragbuf), t); // send it...
				LOG(4, s, t, "MPPP: packet sent as one frame\n");
				update_session_out_stat(s, sp, len);
			}
		}
		else
		{
			// Send it as one frame (NO MPPP Frame)
			uint8_t *p = opt_makeppp(buf, len, s, t, PPPIP, 0, 0, 0);
			tunnelsend(p, len + (buf-p), t); // send it...
			update_session_out_stat(s, sp, len);
		}
	}
	else
	{
		uint8_t *p = opt_makeppp(buf, len, s, t, PPPIP, 0, 0, 0);
		tunnelsend(p, len + (buf-p), t); // send it...
		update_session_out_stat(s, sp, len);
	}

	// Snooping this session, send it to intercept box
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	increment_counter(&sp->cout, &sp->cout_wrap, len); // byte count
	sp->cout_delta += len;
	sp->pout++;
	udp_tx += len;

	sess_local[s].cout += len;	// To send to master..
	sess_local[s].pout++;
}

// process outgoing (to tunnel) IPv6
//
static void processipv6out(uint8_t * buf, int len)
{
	sessionidt s;
	sessiont *sp;
	tunnelidt t;
	struct in6_addr ip6;

	uint8_t *data = buf;	// Keep a copy of the originals.
	int size = len;

	uint8_t b[MAXETHER + 20];

	CSTAT(processipv6out);

	if (len < MIN_IP_SIZE)
	{
		LOG(1, 0, 0, "Short IPv6, %d bytes\n", len);
		STAT(tunnel_tx_errors);
		return;
	}
	if (len >= MAXETHER)
	{
		LOG(1, 0, 0, "Oversize IPv6 packet %d bytes\n", len);
		STAT(tunnel_tx_errors);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	// Got an IP header now
	if (*(uint8_t *)(buf) >> 4 != 6)
	{
		LOG(1, 0, 0, "IP: Don't understand anything except IPv6\n");
		return;
	}

	ip6 = *(struct in6_addr *)(buf+24);
	s = sessionbyipv6(ip6);

	if (s == 0)
	{
		s = sessionbyipv6new(ip6);
	}

	if (s == 0)
	{
		// Is this a packet for a session that doesn't exist?
		static int rate = 0;	// Number of ICMP packets we've sent this second.
		static int last = 0;	// Last time we reset the ICMP packet counter 'rate'.

		if (last != time_now)
		{
			last = time_now;
			rate = 0;
		}

		if (rate++ < config->icmp_rate) // Only send a max of icmp_rate per second.
		{
			// FIXME: Should send icmp6 host unreachable
		}
		return;
	}
	if (session[s].bundle && bundle[session[s].bundle].num_of_links > 1)
	{
		bundleidt bid = session[s].bundle;
		bundlet *b = &bundle[bid];

		b->current_ses = (b->current_ses + 1) % b->num_of_links;
		s = b->members[b->current_ses];
		LOG(3, s, session[s].tunnel, "MPPP: Session number becomes: %u\n", s);
	}
	t = session[s].tunnel;
	sp = &session[s];
	sp->last_data = time_now;

	// FIXME: add DoS prevention/filters?

	if (sp->tbf_out)
	{
		// Are we throttling this session?
		if (config->cluster_iam_master)
			tbf_queue_packet(sp->tbf_out, data, size);
		else
			master_throttle_packet(sp->tbf_out, data, size);
		return;
	}
	else if (sp->walled_garden && !config->cluster_iam_master)
	{
		// We are walled-gardening this
		master_garden_packet(s, data, size);
		return;
	}

	LOG(5, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

	// Add on L2TP header
	{
		uint8_t *p = makeppp(b, sizeof(b), buf, len, s, t, PPPIPV6, 0, 0, 0);
		if (!p) return;
		tunnelsend(b, len + (p-b), t); // send it...
	}

	// Snooping this session, send it to intercept box
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	increment_counter(&sp->cout, &sp->cout_wrap, len); // byte count
	sp->cout_delta += len;
	sp->pout++;
	udp_tx += len;

	sess_local[s].cout += len;	// To send to master..
	sess_local[s].pout++;
}

//
// Helper routine for the TBF filters.
// Used to send queued data in to the user!
//
static void send_ipout(sessionidt s, uint8_t *buf, int len)
{
	sessiont *sp;
	tunnelidt t;
	uint8_t *p;
	uint8_t *data = buf;	// Keep a copy of the originals.

	uint8_t b[MAXETHER + 20];

	if (len < 0 || len > MAXETHER)
	{
		LOG(1, 0, 0, "Odd size IP packet: %d bytes\n", len);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	if (!session[s].ip)
		return;

	t = session[s].tunnel;
	sp = &session[s];

	LOG(5, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

	// Add on L2TP header
	if (*(uint16_t *) (data + 2) == htons(PKTIPV6))
		p = makeppp(b, sizeof(b), buf, len, s, t, PPPIPV6, 0, 0, 0); // IPV6
	else
		p = makeppp(b, sizeof(b), buf, len, s, t, PPPIP, 0, 0, 0); // IPV4

	if (!p) return;

	tunnelsend(b, len + (p-b), t); // send it...

	// Snooping this session.
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	increment_counter(&sp->cout, &sp->cout_wrap, len); // byte count
	sp->cout_delta += len;
	sp->pout++;
	udp_tx += len;

	sess_local[s].cout += len;	// To send to master..
	sess_local[s].pout++;
}

// add an AVP (16 bit)
static void control16(controlt * c, uint16_t avp, uint16_t val, uint8_t m)
{
	uint16_t l = (m ? 0x8008 : 0x0008);
	uint16_t *pint16 = (uint16_t *) (c->buf + c->length + 0);
	pint16[0] = htons(l);
	pint16[1] = htons(0);
	pint16[2] = htons(avp);
	pint16[3] = htons(val);
	c->length += 8;
}

// add an AVP (32 bit)
static void control32(controlt * c, uint16_t avp, uint32_t val, uint8_t m)
{
	uint16_t l = (m ? 0x800A : 0x000A);
	uint16_t *pint16 = (uint16_t *) (c->buf + c->length + 0);
	uint32_t *pint32 = (uint32_t *) (c->buf + c->length + 6);
	pint16[0] = htons(l);
	pint16[1] = htons(0);
	pint16[2] = htons(avp);
	pint32[0] = htonl(val);
	c->length += 10;
}

// add an AVP (string)
static void controls(controlt * c, uint16_t avp, char *val, uint8_t m)
{
	uint16_t l = ((m ? 0x8000 : 0) + strlen(val) + 6);
	uint16_t *pint16 = (uint16_t *) (c->buf + c->length + 0);
	pint16[0] = htons(l);
	pint16[1] = htons(0);
	pint16[2] = htons(avp);
	memcpy(c->buf + c->length + 6, val, strlen(val));
	c->length += 6 + strlen(val);
}

// add a binary AVP
static void controlb(controlt * c, uint16_t avp, uint8_t *val, unsigned int len, uint8_t m)
{
	uint16_t l = ((m ? 0x8000 : 0) + len + 6);
	uint16_t *pint16 = (uint16_t *) (c->buf + c->length + 0);
	pint16[0] = htons(l);
	pint16[1] = htons(0);
	pint16[2] = htons(avp);
	memcpy(c->buf + c->length + 6, val, len);
	c->length += 6 + len;
}

// new control connection
static controlt *controlnew(uint16_t mtype)
{
	controlt *c;
	if (!controlfree)
		c = malloc(sizeof(controlt));
	else
	{
		c = controlfree;
		controlfree = c->next;
	}
	assert(c);
	c->next = 0;
	c->buf[0] = 0xC8; // flags
	c->buf[1] = 0x02; // ver
	c->length = 12;
	control16(c, 0, mtype, 1);
	return c;
}

// send zero block if nothing is waiting
// (ZLB send).
static void controlnull(tunnelidt t)
{
	uint16_t buf[6];
	if (tunnel[t].controlc)	// Messages queued; They will carry the ack.
		return;

	buf[0] = htons(0xC802); // flags/ver
	buf[1] = htons(12); // length
	buf[2] = htons(tunnel[t].far); // tunnel
	buf[3] = htons(0); // session
	buf[4] = htons(tunnel[t].ns); // sequence
	buf[5] = htons(tunnel[t].nr); // sequence
	tunnelsend((uint8_t *)buf, 12, t);
}

// add a control message to a tunnel, and send if within window
static void controladd(controlt *c, sessionidt far, tunnelidt t)
{
	uint16_t *pint16 = (uint16_t *) (c->buf + 2);
	pint16[0] = htons(c->length); // length
	pint16[1] = htons(tunnel[t].far); // tunnel
	pint16[2] = htons(far); // session
	pint16[3] = htons(tunnel[t].ns); // sequence
	tunnel[t].ns++;              // advance sequence
	// link in message in to queue
	if (tunnel[t].controlc)
		tunnel[t].controle->next = c;
	else
		tunnel[t].controls = c;

	tunnel[t].controle = c;
	tunnel[t].controlc++;

	// send now if space in window
	if (tunnel[t].controlc <= tunnel[t].window)
	{
		tunnel[t].try = 0;      // first send
		tunnelsend(c->buf, c->length, t);
	}
}

//
// Throttle or Unthrottle a session
//
// Throttle the data from/to through a session to no more than
// 'rate_in' kbit/sec in (from user) or 'rate_out' kbit/sec out (to
// user).
//
// If either value is -1, the current value is retained for that
// direction.
//
void throttle_session(sessionidt s, int rate_in, int rate_out)
{
	if (!session[s].opened)
		return; // No-one home.

	if (!*session[s].user)
	        return; // User not logged in

	if (rate_in >= 0)
	{
		int bytes = rate_in * 1024 / 8; // kbits to bytes
		if (session[s].tbf_in)
			free_tbf(session[s].tbf_in);

		if (rate_in > 0)
			session[s].tbf_in = new_tbf(s, bytes * 2, bytes, send_ipin);
		else
			session[s].tbf_in = 0;

		session[s].throttle_in = rate_in;
	}

	if (rate_out >= 0)
	{
		int bytes = rate_out * 1024 / 8;
		if (session[s].tbf_out)
			free_tbf(session[s].tbf_out);

		if (rate_out > 0)
			session[s].tbf_out = new_tbf(s, bytes * 2, bytes, send_ipout);
		else
			session[s].tbf_out = 0;

		session[s].throttle_out = rate_out;
	}

	#ifdef ISEEK_CONTROL_MESSAGE
	LOG(1, s, session[s].tunnel, "iseek-control-message throttle %s %d/%d %s %d/%d\n", session[s].user, session[s].tx_connect_speed, session[s].rx_connect_speed, fmtaddr(htonl(session[s].ip), 0), session[s].throttle_in, session[s].throttle_out);
	#endif

}

// add/remove filters from session (-1 = no change)
void filter_session(sessionidt s, int filter_in, int filter_out)
{
	if (!session[s].opened)
		return; // No-one home.

	if (!*session[s].user)
	        return; // User not logged in

	// paranoia
	if (filter_in > MAXFILTER) filter_in = -1;
	if (filter_out > MAXFILTER) filter_out = -1;
	if (session[s].filter_in > MAXFILTER) session[s].filter_in = 0;
	if (session[s].filter_out > MAXFILTER) session[s].filter_out = 0;

	if (filter_in >= 0)
	{
		if (session[s].filter_in)
			ip_filters[session[s].filter_in - 1].used--;

		if (filter_in > 0)
			ip_filters[filter_in - 1].used++;

		session[s].filter_in = filter_in;
	}

	if (filter_out >= 0)
	{
		if (session[s].filter_out)
			ip_filters[session[s].filter_out - 1].used--;

		if (filter_out > 0)
			ip_filters[filter_out - 1].used++;

		session[s].filter_out = filter_out;
	}
}

// start tidy shutdown of session
void sessionshutdown(sessionidt s, char const *reason, int cdn_result, int cdn_error, int term_cause)
{
	int walled_garden = session[s].walled_garden;
	bundleidt b = session[s].bundle;
	//delete routes only for last session in bundle (in case of MPPP)
	int del_routes = !b || (bundle[b].num_of_links == 1);

	CSTAT(sessionshutdown);

	if (!session[s].opened)
	{
		LOG(3, s, session[s].tunnel, "Called sessionshutdown on an unopened session.\n");
		return;                   // not a live session
	}

	if (!session[s].die)
	{
		struct param_kill_session data = { &tunnel[session[s].tunnel], &session[s] };
		LOG(2, s, session[s].tunnel, "Shutting down session %u: %s\n", s, reason);
		run_plugins(PLUGIN_KILL_SESSION, &data);
	}

	if (session[s].ip && !walled_garden && !session[s].die)
	{
		// RADIUS Stop message
		uint16_t r = radiusnew(s);
		if (r)
		{
			// stop, if not already trying
			if (radius[r].state != RADIUSSTOP)
			{
				radius[r].term_cause = term_cause;
				radius[r].term_msg = reason;
				radiussend(r, RADIUSSTOP);
			}
		}
		else
			LOG(1, s, session[s].tunnel, "No free radius sessions for Stop message\n");

		// Save counters to dump to accounting file
		if (*config->accounting_dir && shut_acct_n < sizeof(shut_acct) / sizeof(*shut_acct))
			memcpy(&shut_acct[shut_acct_n++], &session[s], sizeof(session[s]));
	} 
	else LOG(1, s, session[s].tunnel, "EKL: Not sending radius stop\n");

	#ifdef ISEEK_CONTROL_MESSAGE
	    LOG(1, s, session[s].tunnel, "iseek-control-message logout %s %d/%d %s\n", session[s].user, session[s].tx_connect_speed, session[s].rx_connect_speed, fmtaddr(htonl(session[s].ip), 0));
	#endif

	if (!session[s].die)
		session[s].die = TIME + 150; // Clean up in 15 seconds

	if (session[s].ip)
	{                          // IP allocated, clear and unroute
		int r;
		int routed = 0;
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			if ((session[s].ip >> (32-session[s].route[r].prefixlen)) ==
			    (session[s].route[r].ip >> (32-session[s].route[r].prefixlen)))
				routed++;

			if (del_routes) routeset(s, session[s].route[r].ip, session[s].route[r].prefixlen, 0, 0);
			session[s].route[r].ip = 0;
		}

		if (session[s].ip_pool_index == -1) // static ip
		{
			if (!routed && del_routes) routeset(s, session[s].ip, 0, 0, 0);
			session[s].ip = 0;
		}
		else
			free_ip_address(s);

		// unroute IPv6, if setup
		for (r = 0; r < MAXROUTE6 && session[s].route6[r].ipv6route.s6_addr[0] && session[s].route6[r].ipv6prefixlen; r++)
		{
			if (del_routes) route6set(s, session[s].route6[r].ipv6route, session[s].route6[r].ipv6prefixlen, 0);
			memset(&session[s].route6[r], 0, sizeof(session[s].route6[r]));
		}

		if (session[s].ipv6address.s6_addr[0] && del_routes)
		{
			route6set(s, session[s].ipv6address, 128, 0);
		}

		if (b)
		{
			// This session was part of a bundle
			bundle[b].num_of_links--;
			LOG(3, s, session[s].tunnel, "MPPP: Dropping member link: %d from bundle %d\n",s,b);
			if(bundle[b].num_of_links == 0)
			{
				bundleclear(b);
				LOG(3, s, session[s].tunnel, "MPPP: Kill bundle: %d (No remaing member links)\n",b);
			}
			else 
			{
				// Adjust the members array to accomodate the new change
				uint8_t mem_num = 0;
				// It should be here num_of_links instead of num_of_links-1 (previous instruction "num_of_links--")
				if(bundle[b].members[bundle[b].num_of_links] != s)
				{
					uint8_t ml;
					for(ml = 0; ml<bundle[b].num_of_links; ml++)
					if(bundle[b].members[ml] == s)
					{
							mem_num = ml;
							break;
					}
					bundle[b].members[mem_num] = bundle[b].members[bundle[b].num_of_links];
					LOG(3, s, session[s].tunnel, "MPPP: Adjusted member links array\n");

					// If the killed session is the first of the bundle,
					// the new first session must be stored in the cache_ipmap
					// else the function sessionbyip return 0 and the sending not work any more (processipout).
					if (mem_num == 0)
					{
						sessionidt new_s = bundle[b].members[0];

						routed = 0;
						// Add the route for this session.
						for (r = 0; r < MAXROUTE && session[new_s].route[r].ip; r++)
						{
							int i, prefixlen;
							in_addr_t ip;

							prefixlen = session[new_s].route[r].prefixlen;
							ip = session[new_s].route[r].ip;

							if (!prefixlen) prefixlen = 32;
							ip &= 0xffffffff << (32 - prefixlen);	// Force the ip to be the first one in the route.

							for (i = ip; i < ip+(1<<(32-prefixlen)) ; ++i)
								cache_ipmap(i, new_s);
						}
						cache_ipmap(session[new_s].ip, new_s);

						// IPV6 route
						for (r = 0; r < MAXROUTE6 && session[new_s].route6[r].ipv6prefixlen; r++)
						{
							cache_ipv6map(session[new_s].route6[r].ipv6route, session[new_s].route6[r].ipv6prefixlen, new_s);
						}

						if (session[new_s].ipv6address.s6_addr[0])
						{
							cache_ipv6map(session[new_s].ipv6address, 128, new_s);
						}
					}
				}
			}

			cluster_send_bundle(b);
        	}
	}

	if (session[s].throttle_in || session[s].throttle_out) // Unthrottle if throttled.
		throttle_session(s, 0, 0);

	if (cdn_result)
	{
		if (session[s].tunnel == TUNNEL_ID_PPPOE)
		{
			pppoe_shutdown_session(s);
		}
		else
		{
			// Send CDN
			controlt *c = controlnew(14); // sending CDN
			if (cdn_error)
			{
				uint16_t buf[2];
				buf[0] = htons(cdn_result);
				buf[1] = htons(cdn_error);
				controlb(c, 1, (uint8_t *)buf, 4, 1);
			}
			else
				control16(c, 1, cdn_result, 1);

			control16(c, 14, s, 1);   // assigned session (our end)
			controladd(c, session[s].far, session[s].tunnel); // send the message
		}
	}

	// update filter refcounts
	if (session[s].filter_in) ip_filters[session[s].filter_in - 1].used--;
	if (session[s].filter_out) ip_filters[session[s].filter_out - 1].used--;

	// clear PPP state
	memset(&session[s].ppp, 0, sizeof(session[s].ppp));
	sess_local[s].lcp.restart = 0;
	sess_local[s].ipcp.restart = 0;
	sess_local[s].ipv6cp.restart = 0;
	sess_local[s].ccp.restart = 0;

	cluster_send_session(s);
}

void sendipcp(sessionidt s, tunnelidt t)
{
	uint8_t buf[MAXETHER];
	uint8_t *q;

	CSTAT(sendipcp);
	LOG(3, s, t, "IPCP: send ConfigReq\n");

	if (!session[s].unique_id)
	{
		if (!++last_id) ++last_id; // skip zero
		session[s].unique_id = last_id;
	}

	q = makeppp(buf, sizeof(buf), 0, 0, s, t, PPPIPCP, 0, 0, 0);
	if (!q) return;

	*q = ConfigReq;
	q[1] = session[s].unique_id & 0xf;	// ID, dont care, we only send one type of request
	*(uint16_t *) (q + 2) = htons(10);	// packet length
	q[4] = 3;				// ip address option
	q[5] = 6;				// option length
	*(in_addr_t *) (q + 6) = config->peer_address ? config->peer_address :
				 config->iftun_n_address[tunnel[t].indexudp] ? config->iftun_n_address[tunnel[t].indexudp] :
				 my_address; // send my IP

	tunnelsend(buf, 10 + (q - buf), t); // send it
	restart_timer(s, ipcp);
}

void sendipv6cp(sessionidt s, tunnelidt t)
{
	uint8_t buf[MAXETHER];
	uint8_t *q;

	CSTAT(sendipv6cp);
	LOG(3, s, t, "IPV6CP: send ConfigReq\n");

	q = makeppp(buf, sizeof(buf), 0, 0, s, t, PPPIPV6CP, 0, 0, 0);
	if (!q) return;

	*q = ConfigReq;
	q[1] = session[s].unique_id & 0xf;	// ID, don't care, we
						// only send one type
						// of request
	*(uint16_t *) (q + 2) = htons(14);
	q[4] = 1;				// interface identifier option
	q[5] = 10;				// option length
	*(uint32_t *) (q + 6) = 0;		// We'll be prefix::1
	*(uint32_t *) (q + 10) = 0;
	q[13] = 1;

	tunnelsend(buf, 14 + (q - buf), t);	// send it
	restart_timer(s, ipv6cp);
}

static void sessionclear(sessionidt s)
{
	memset(&session[s], 0, sizeof(session[s]));
	memset(&sess_local[s], 0, sizeof(sess_local[s]));
	memset(&cli_session_actions[s], 0, sizeof(cli_session_actions[s]));

	session[s].tunnel = T_FREE;	// Mark it as free.
	session[s].next = sessionfree;
	sessionfree = s;
}

// kill a session now
void sessionkill(sessionidt s, char *reason)
{
	CSTAT(sessionkill);

	if (!session[s].opened) // not alive
		return;

	if (session[s].next)
	{
		LOG(0, s, session[s].tunnel, "Tried to kill a session with next pointer set (%u)\n", session[s].next);
		return;
	}

	if (!session[s].die)
		sessionshutdown(s, reason, CDN_ADMIN_DISC, TERM_ADMIN_RESET);  // close radius/routes, etc.

	if (sess_local[s].radius)
		radiusclear(sess_local[s].radius, s); // cant send clean accounting data, session is killed

	if (session[s].forwardtosession)
	{
		sessionidt sess = session[s].forwardtosession;
		if (session[sess].forwardtosession == s)
		{
			// Shutdown the linked session also.
			sessionshutdown(sess, reason, CDN_ADMIN_DISC, TERM_ADMIN_RESET);
		}
	}

	LOG(2, s, session[s].tunnel, "Kill session %d (%s): %s\n", s, session[s].user, reason);
	sessionclear(s);
	cluster_send_session(s);
}

static void tunnelclear(tunnelidt t)
{
	if (!t) return;
	memset(&tunnel[t], 0, sizeof(tunnel[t]));
	tunnel[t].state = TUNNELFREE;
}

static void bundleclear(bundleidt b)
{
	if (!b) return;
	memset(&bundle[b], 0, sizeof(bundle[b]));
	bundle[b].state = BUNDLEFREE;
}

// kill a tunnel now
static void tunnelkill(tunnelidt t, char *reason)
{
	sessionidt s;
	controlt *c;

	CSTAT(tunnelkill);

	tunnel[t].state = TUNNELDIE;

	// free control messages
	while ((c = tunnel[t].controls))
	{
		controlt * n = c->next;
		tunnel[t].controls = n;
		tunnel[t].controlc--;
		c->next = controlfree;
		controlfree = c;
	}
	// kill sessions
	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
		if (session[s].tunnel == t)
			sessionkill(s, reason);

	// free tunnel
	tunnelclear(t);
	LOG(1, 0, t, "Kill tunnel %u: %s\n", t, reason);
	cli_tunnel_actions[t].action = 0;
	cluster_send_tunnel(t);
}

// shut down a tunnel cleanly
static void tunnelshutdown(tunnelidt t, char *reason, int result, int error, char *msg)
{
	sessionidt s;

	CSTAT(tunnelshutdown);

	if (!tunnel[t].last || !tunnel[t].far || tunnel[t].state == TUNNELFREE)
	{
		// never set up, can immediately kill
		tunnelkill(t, reason);
		return;
	}
	LOG(1, 0, t, "Shutting down tunnel %u (%s)\n", t, reason);

	// close session
	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
		if (session[s].tunnel == t)
			sessionshutdown(s, reason, CDN_NONE, TERM_ADMIN_RESET);

	tunnel[t].state = TUNNELDIE;
	tunnel[t].die = TIME + 700; // Clean up in 70 seconds
	cluster_send_tunnel(t);
	// TBA - should we wait for sessions to stop?
	if (result) 
	{
		controlt *c = controlnew(4);	// sending StopCCN
		if (error)
		{
			uint16_t buf[32];
			int l = 4;
			buf[0] = htons(result);
			buf[1] = htons(error);
			if (msg)
			{
				int m = strlen(msg);
				if (m + 4 > sizeof(buf))
				    m = sizeof(buf) - 4;

				memcpy(buf+2, msg, m);
				l += m;
			}

			controlb(c, 1, (uint8_t *)buf, l, 1);
		}
		else
			control16(c, 1, result, 1);

		control16(c, 9, t, 1);		// assigned tunnel (our end)
		controladd(c, 0, t);		// send the message
	}
}

int count_current_sessions()
{
	return GET_STAT(session_created) - GET_STAT(call_sessionkill);
}

int check_sessions ()
{
	int *maxallowed = (int *)getconfig("max_sessions", INT);
	if (*maxallowed == 0)
		return 1;

#ifdef STATISTICS
	int connected = count_current_sessions();
	if (connected >= *maxallowed)
		return 0;
	else
#endif
		return 1;
}

// read and process packet on tunnel (UDP)
void processudp(uint8_t *buf, int len, struct sockaddr_in *addr, uint16_t indexudpfd)
{
	uint8_t *sendchalresponse = NULL;
	uint8_t *recvchalresponse = NULL;
	uint16_t l = len, t = 0, s = 0, ns = 0, nr = 0;
	uint8_t *p = buf + 2;


	CSTAT(processudp);

	udp_rx += len;
	udp_rx_pkt++;
	LOG_HEX(5, "UDP Data", buf, len);
	STAT(tunnel_rx_packets);
	INC_STAT(tunnel_rx_bytes, len);
	if (len < 6)
	{
		LOG(1, 0, 0, "Short UDP, %d bytes\n", len);
		STAT(tunnel_rx_errors);
		return;
	}
	if ((buf[1] & 0x0F) != 2)
	{
		LOG(1, 0, 0, "Bad L2TP ver %d\n", buf[1] & 0x0F);
		STAT(tunnel_rx_errors);
		return;
	}
	if (*buf & 0x40)
	{                          // length
		l = ntohs(*(uint16_t *) p);
		p += 2;
	}
	t = ntohs(*(uint16_t *) p);
	p += 2;
	s = ntohs(*(uint16_t *) p);
	p += 2;
	if (s >= MAXSESSION)
	{
		LOG(1, s, t, "Received UDP packet with invalid session ID\n");
		STAT(tunnel_rx_errors);
		return;
	}
	if (t >= MAXTUNNEL)
	{
		LOG(1, s, t, "Received UDP packet with invalid tunnel ID\n");
		STAT(tunnel_rx_errors);
		return;
	}
	if (t == TUNNEL_ID_PPPOE)
	{
		LOG(1, s, t, "Received UDP packet with tunnel ID reserved for pppoe\n");
		STAT(tunnel_rx_errors);
		return;
	}
	if (*buf & 0x08)
	{                          // ns/nr
		ns = ntohs(*(uint16_t *) p);
		p += 2;
		nr = ntohs(*(uint16_t *) p);
		p += 2;
	}
	if (*buf & 0x02)
	{                          // offset
		uint16_t o = ntohs(*(uint16_t *) p);
		p += o + 2;
	}
	if ((p - buf) > l)
	{
		LOG(1, s, t, "Bad length %d>%d\n", (int) (p - buf), l);
		STAT(tunnel_rx_errors);
		return;
	}
	l -= (p - buf);

	// used to time out old tunnels
	if (t && tunnel[t].state == TUNNELOPEN)
		tunnel[t].lastrec = time_now;

	if (*buf & 0x80)
	{                          // control
		uint16_t message = 0xFFFF;	// message type
		uint8_t fatal = 0;
		uint8_t mandatory = 0;
		uint16_t asession = 0;		// assigned session
		uint32_t amagic = 0;		// magic number
		uint8_t aflags = 0;		// flags from last LCF
		uint16_t version = 0x0100;	// protocol version (we handle 0.0 as well and send that back just in case)
		char called[MAXTEL] = "";	// called number
		char calling[MAXTEL] = "";	// calling number

		if (!config->cluster_iam_master)
		{
			master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd);
			return;
		}

		// control messages must have bits 0x80|0x40|0x08
		// (type, length and sequence) set, and bits 0x02|0x01
		// (offset and priority) clear
		if ((*buf & 0xCB) != 0xC8)
		{
			LOG(1, s, t, "Bad control header %02X\n", *buf);
			STAT(tunnel_rx_errors);
			return;
		}

		// check for duplicate tunnel open message
		if (!t && ns == 0)
		{
			int i;

				//
				// Is this a duplicate of the first packet? (SCCRQ)
				//
			for (i = 1; i <= config->cluster_highest_tunnelid ; ++i)
			{
				if (tunnel[i].state != TUNNELOPENING ||
					tunnel[i].ip != ntohl(*(in_addr_t *) & addr->sin_addr) ||
					tunnel[i].port != ntohs(addr->sin_port) )
					continue;
				t = i;
				LOG(3, s, t, "Duplicate SCCRQ?\n");
				break;
			}
		}

		LOG(3, s, t, "Control message (%d bytes): (unacked %d) l-ns %u l-nr %u r-ns %u r-nr %u\n",
			l, tunnel[t].controlc, tunnel[t].ns, tunnel[t].nr, ns, nr);

		// if no tunnel specified, assign one
		if (!t)
		{
			if (!(t = new_tunnel()))
			{
				LOG(1, 0, 0, "No more tunnels\n");
				STAT(tunnel_overflow);
				return;
			}
			tunnelclear(t);
			tunnel[t].ip = ntohl(*(in_addr_t *) & addr->sin_addr);
			tunnel[t].port = ntohs(addr->sin_port);
			tunnel[t].window = 4; // default window
			tunnel[t].indexudp = indexudpfd;
			STAT(tunnel_created);
			LOG(1, 0, t, "   New tunnel from %s:%u ID %u\n",
				fmtaddr(htonl(tunnel[t].ip), 0), tunnel[t].port, t);
		}

			// If the 'ns' just received is not the 'nr' we're
			// expecting, just send an ack and drop it.
			//
			// if 'ns' is less, then we got a retransmitted packet.
			// if 'ns' is greater than missed a packet. Either way
			// we should ignore it.
		if (ns != tunnel[t].nr)
		{
			// is this the sequence we were expecting?
			STAT(tunnel_rx_errors);
			LOG(1, 0, t, "   Out of sequence tunnel %u, (%u is not the expected %u)\n",
				t, ns, tunnel[t].nr);

			if (l)	// Is this not a ZLB?
				controlnull(t);
			return;
		}

		// check sequence of this message
		{
			int skip = tunnel[t].window; // track how many in-window packets are still in queue
				// some to clear maybe?
			while (tunnel[t].controlc > 0 && (((tunnel[t].ns - tunnel[t].controlc) - nr) & 0x8000))
			{
				controlt *c = tunnel[t].controls;
				tunnel[t].controls = c->next;
				tunnel[t].controlc--;
				c->next = controlfree;
				controlfree = c;
				skip--;
				tunnel[t].try = 0; // we have progress
			}

			// receiver advance (do here so quoted correctly in any sends below)
			if (l) tunnel[t].nr = (ns + 1);
			if (skip < 0) skip = 0;
			if (skip < tunnel[t].controlc)
			{
				// some control packets can now be sent that were previous stuck out of window
				int tosend = tunnel[t].window - skip;
				controlt *c = tunnel[t].controls;
				while (c && skip)
				{
					c = c->next;
					skip--;
				}
				while (c && tosend)
				{
					tunnel[t].try = 0; // first send
					tunnelsend(c->buf, c->length, t);
					c = c->next;
					tosend--;
				}
			}
			if (!tunnel[t].controlc)
				tunnel[t].retry = 0; // caught up
		}
		if (l)
		{                     // if not a null message
			int result = 0;
			int error = 0;
			char *msg = 0;

			// Default disconnect cause/message on receipt of CDN.  Set to
			// more specific value from attribute 1 (result code) or 46
			// (disconnect cause) if present below.
			int disc_cause_set = 0;
			int disc_cause = TERM_NAS_REQUEST;
			char const *disc_reason = "Closed (Received CDN).";

			// process AVPs
			while (l && !(fatal & 0x80)) // 0x80 = mandatory AVP
			{
				uint16_t n = (ntohs(*(uint16_t *) p) & 0x3FF);
				uint8_t *b = p;
				uint8_t flags = *p;
				uint16_t mtype;

				if (n > l)
				{
					LOG(1, s, t, "Invalid length in AVP\n");
					STAT(tunnel_rx_errors);
					return;
				}
				p += n;       // next
				l -= n;
				if (flags & 0x3C) // reserved bits, should be clear
				{
					LOG(1, s, t, "Unrecognised AVP flags %02X\n", *b);
					fatal = flags;
					result = 2; // general error
					error = 3; // reserved field non-zero
					msg = 0;
					continue; // next
				}
				b += 2;
				if (*(uint16_t *) (b))
				{
					LOG(2, s, t, "Unknown AVP vendor %u\n", ntohs(*(uint16_t *) (b)));
					fatal = flags;
					result = 2; // general error
					error = 6; // generic vendor-specific error
					msg = "unsupported vendor-specific";
					continue; // next
				}
				b += 2;
				mtype = ntohs(*(uint16_t *) (b));
				b += 2;
				n -= 6;

				if (flags & 0x40)
				{
					uint16_t orig_len;

					// handle hidden AVPs
					if (!*config->l2tp_secret)
					{
						LOG(1, s, t, "Hidden AVP requested, but no L2TP secret.\n");
						fatal = flags;
						result = 2; // general error
						error = 6; // generic vendor-specific error
						msg = "secret not specified";
						continue;
					}
					if (!session[s].random_vector_length)
					{
						LOG(1, s, t, "Hidden AVP requested, but no random vector.\n");
						fatal = flags;
						result = 2; // general error
						error = 6; // generic
						msg = "no random vector";
						continue;
					}
					if (n < 8)
					{
						LOG(2, s, t, "Short hidden AVP.\n");
						fatal = flags;
						result = 2; // general error
						error = 2; // length is wrong
						msg = 0;
						continue;
					}

					// Unhide the AVP
					unhide_value(b, n, mtype, session[s].random_vector, session[s].random_vector_length);

					orig_len = ntohs(*(uint16_t *) b);
					if (orig_len > n + 2)
					{
						LOG(1, s, t, "Original length %d too long in hidden AVP of length %d; wrong secret?\n",
						    orig_len, n);

						fatal = flags;
						result = 2; // general error
						error = 2; // length is wrong
						msg = 0;
						continue;
					}

					b += 2;
					n = orig_len;
				}

				LOG(4, s, t, "   AVP %u (%s) len %d%s%s\n", mtype, l2tp_avp_name(mtype), n,
					flags & 0x40 ? ", hidden" : "", flags & 0x80 ? ", mandatory" : "");

				switch (mtype)
				{
				case 0:     // message type
					message = ntohs(*(uint16_t *) b);
					mandatory = flags & 0x80;
					LOG(4, s, t, "   Message type = %u (%s)\n", message, l2tp_code(message));
					break;
				case 1:     // result code
					{
						uint16_t rescode = ntohs(*(uint16_t *) b);
						char const *resdesc = "(unknown)";
						char const *errdesc = NULL;
						int cause = 0;

						if (message == 4)
						{ /* StopCCN */
							resdesc = l2tp_stopccn_result_code(rescode);
							cause = TERM_LOST_SERVICE;
						}
						else if (message == 14)
						{ /* CDN */
							resdesc = l2tp_cdn_result_code(rescode);
							if (rescode == 1)
								cause = TERM_LOST_CARRIER;
							else
								cause = TERM_ADMIN_RESET;
						}

						LOG(4, s, t, "   Result Code %u: %s\n", rescode, resdesc);
						if (n >= 4)
						{
							uint16_t errcode = ntohs(*(uint16_t *)(b + 2));
							errdesc = l2tp_error_code(errcode);
							LOG(4, s, t, "   Error Code %u: %s\n", errcode, errdesc);
						}
						if (n > 4)
							LOG(4, s, t, "   Error String: %.*s\n", n-4, b+4);

						if (cause && disc_cause_set < mtype) // take cause from attrib 46 in preference
						{
							disc_cause_set = mtype;
							disc_reason = errdesc ? errdesc : resdesc;
							disc_cause = cause;
						}

						break;
					}
					break;
				case 2:     // protocol version
					{
						version = ntohs(*(uint16_t *) (b));
						LOG(4, s, t, "   Protocol version = %u\n", version);
						if (version && version != 0x0100)
						{   // allow 0.0 and 1.0
							LOG(1, s, t, "   Bad protocol version %04X\n", version);
							fatal = flags;
							result = 5; // unspported protocol version
							error = 0x0100; // supported version
							msg = 0;
							continue; // next
						}
					}
					break;
				case 3:     // framing capabilities
					break;
				case 4:     // bearer capabilities
					break;
				case 5:		// tie breaker
					// We never open tunnels, so we don't care about tie breakers
					continue;
				case 6:     // firmware revision
					break;
				case 7:     // host name
					memset(tunnel[t].hostname, 0, sizeof(tunnel[t].hostname));
					memcpy(tunnel[t].hostname, b, (n < sizeof(tunnel[t].hostname)) ? n : sizeof(tunnel[t].hostname) - 1);
					LOG(4, s, t, "   Tunnel hostname = \"%s\"\n", tunnel[t].hostname);
					// TBA - to send to RADIUS
					break;
				case 8:     // vendor name
					memset(tunnel[t].vendor, 0, sizeof(tunnel[t].vendor));
					memcpy(tunnel[t].vendor, b, (n < sizeof(tunnel[t].vendor)) ? n : sizeof(tunnel[t].vendor) - 1);
					LOG(4, s, t, "   Vendor name = \"%s\"\n", tunnel[t].vendor);
					break;
				case 9:     // assigned tunnel
					tunnel[t].far = ntohs(*(uint16_t *) (b));
					LOG(4, s, t, "   Remote tunnel id = %u\n", tunnel[t].far);
					break;
				case 10:    // rx window
					tunnel[t].window = ntohs(*(uint16_t *) (b));
					if (!tunnel[t].window)
						tunnel[t].window = 1; // window of 0 is silly
					LOG(4, s, t, "   rx window = %u\n", tunnel[t].window);
					break;
				case 11:	// Request Challenge
					{
						LOG(4, s, t, "   LAC requested CHAP authentication for tunnel\n");
						if (message == 1)
							build_chap_response(b, 2, n, &sendchalresponse);
						else if (message == 2)
							build_chap_response(b, 3, n, &sendchalresponse);
					}
					break;
				case 13:    // receive challenge Response
					if (tunnel[t].isremotelns)
					{
						recvchalresponse = calloc(17, 1);
						memcpy(recvchalresponse, b, (n < 17) ? n : 16);
						LOG(3, s, t, "received challenge response from REMOTE LNS\n");
					}
					else
					// Why did they send a response? We never challenge.
					LOG(2, s, t, "   received unexpected challenge response\n");
					break;

				case 14:    // assigned session
					asession = session[s].far = ntohs(*(uint16_t *) (b));
					LOG(4, s, t, "   assigned session = %u\n", asession);
					break;
				case 15:    // call serial number
					LOG(4, s, t, "   call serial number = %u\n", ntohl(*(uint32_t *)b));
					break;
				case 18:    // bearer type
					LOG(4, s, t, "   bearer type = %u\n", ntohl(*(uint32_t *)b));
					// TBA - for RADIUS
					break;
				case 19:    // framing type
					LOG(4, s, t, "   framing type = %u\n", ntohl(*(uint32_t *)b));
					// TBA
					break;
				case 21:    // called number
					memset(called, 0, sizeof(called));
					memcpy(called, b, (n < sizeof(called)) ? n : sizeof(called) - 1);
					LOG(4, s, t, "   Called <%s>\n", called);
					break;
				case 22:    // calling number
					memset(calling, 0, sizeof(calling));
					memcpy(calling, b, (n < sizeof(calling)) ? n : sizeof(calling) - 1);
					LOG(4, s, t, "   Calling <%s>\n", calling);
					break;
				case 23:    // subtype
					break;
				case 24:    // tx connect speed
					if (n == 4)
					{
						session[s].tx_connect_speed = ntohl(*(uint32_t *)b);
					}
					else
					{
						// AS5300s send connect speed as a string
						char tmp[30];
						memset(tmp, 0, sizeof(tmp));
						memcpy(tmp, b, (n < sizeof(tmp)) ? n : sizeof(tmp) - 1);
						session[s].tx_connect_speed = atol(tmp);
					}
					LOG(4, s, t, "   TX connect speed <%u>\n", session[s].tx_connect_speed);
					break;
				case 38:    // rx connect speed
					if (n == 4)
					{
						session[s].rx_connect_speed = ntohl(*(uint32_t *)b);
					}
					else
					{
						// AS5300s send connect speed as a string
						char tmp[30];
						memset(tmp, 0, sizeof(tmp));
						memcpy(tmp, b, (n < sizeof(tmp)) ? n : sizeof(tmp) - 1);
						session[s].rx_connect_speed = atol(tmp);
					}
					LOG(4, s, t, "   RX connect speed <%u>\n", session[s].rx_connect_speed);
					break;
				case 25:    // Physical Channel ID
					{
						uint32_t tmp = ntohl(*(uint32_t *) b);
						LOG(4, s, t, "   Physical Channel ID <%X>\n", tmp);
						break;
					}
				case 29:    // Proxy Authentication Type
					{
						uint16_t atype = ntohs(*(uint16_t *)b);
						LOG(4, s, t, "   Proxy Auth Type %u (%s)\n", atype, ppp_auth_type(atype));
						break;
					}
				case 30:    // Proxy Authentication Name
					{
						char authname[64];
						memset(authname, 0, sizeof(authname));
						memcpy(authname, b, (n < sizeof(authname)) ? n : sizeof(authname) - 1);
						LOG(4, s, t, "   Proxy Auth Name (%s)\n",
							authname);
						break;
					}
				case 31:    // Proxy Authentication Challenge
					{
						LOG(4, s, t, "   Proxy Auth Challenge\n");
						break;
					}
				case 32:    // Proxy Authentication ID
					{
						uint16_t authid = ntohs(*(uint16_t *)(b));
						LOG(4, s, t, "   Proxy Auth ID (%u)\n", authid);
						break;
					}
				case 33:    // Proxy Authentication Response
					LOG(4, s, t, "   Proxy Auth Response\n");
					break;
				case 27:    // last sent lcp
					{        // find magic number
						uint8_t *p = b, *e = p + n;
						while (p + 1 < e && p[1] && p + p[1] <= e)
						{
							if (*p == 5 && p[1] == 6) // Magic-Number
								amagic = ntohl(*(uint32_t *) (p + 2));
							else if (*p == 7) // Protocol-Field-Compression
								aflags |= SESSION_PFC;
							else if (*p == 8) // Address-and-Control-Field-Compression
								aflags |= SESSION_ACFC;
							p += p[1];
						}
					}
					break;
				case 28:    // last recv lcp confreq
					break;
				case 26:    // Initial Received LCP CONFREQ
					break;
				case 39:    // seq required - we control it as an LNS anyway...
					break;
				case 36:    // Random Vector
					LOG(4, s, t, "   Random Vector received.  Enabled AVP Hiding.\n");
					memset(session[s].random_vector, 0, sizeof(session[s].random_vector));
					if (n > sizeof(session[s].random_vector))
						n = sizeof(session[s].random_vector);
					memcpy(session[s].random_vector, b, n);
					session[s].random_vector_length = n;
					break;
				case 46:    // ppp disconnect cause
					if (n >= 5)
					{
						uint16_t code = ntohs(*(uint16_t *) b);
						uint16_t proto = ntohs(*(uint16_t *) (b + 2));
						uint8_t dir = *(b + 4);

						LOG(4, s, t, "   PPP disconnect cause "
							"(code=%u, proto=%04X, dir=%u, msg=\"%.*s\")\n",
							code, proto, dir, n - 5, b + 5);

						disc_cause_set = mtype;

						switch (code)
						{
						case 1: // admin disconnect
							disc_cause = TERM_ADMIN_RESET;
							disc_reason = "Administrative disconnect";
							break;
						case 3: // lcp terminate
							if (dir != 2) break; // 1=peer (LNS), 2=local (LAC)
							disc_cause = TERM_USER_REQUEST;
							disc_reason = "Normal disconnection";
							break;
						case 4: // compulsory encryption unavailable
							if (dir != 1) break; // 1=refused by peer, 2=local
							disc_cause = TERM_USER_ERROR;
							disc_reason = "Compulsory encryption refused";
							break;
						case 5: // lcp: fsm timeout
							disc_cause = TERM_PORT_ERROR;
							disc_reason = "LCP: FSM timeout";
							break;
						case 6: // lcp: no recognisable lcp packets received
							disc_cause = TERM_PORT_ERROR;
							disc_reason = "LCP: no recognisable LCP packets";
							break;
						case 7: // lcp: magic-no error (possibly looped back)
							disc_cause = TERM_PORT_ERROR;
							disc_reason = "LCP: magic-no error (possible loop)";
							break;
						case 8: // lcp: echo request timeout
							disc_cause = TERM_PORT_ERROR;
							disc_reason = "LCP: echo request timeout";
							break;
						case 13: // auth: fsm timeout
							disc_cause = TERM_SERVICE_UNAVAILABLE;
							disc_reason = "Authentication: FSM timeout";
							break;
						case 15: // auth: unacceptable auth protocol
							disc_cause = TERM_SERVICE_UNAVAILABLE;
							disc_reason = "Unacceptable authentication protocol";
							break;
						case 16: // auth: authentication failed
							disc_cause = TERM_SERVICE_UNAVAILABLE;
							disc_reason = "Authentication failed";
							break;
						case 17: // ncp: fsm timeout
							disc_cause = TERM_SERVICE_UNAVAILABLE;
							disc_reason = "NCP: FSM timeout";
							break;
						case 18: // ncp: no ncps available
							disc_cause = TERM_SERVICE_UNAVAILABLE;
							disc_reason = "NCP: no NCPs available";
							break;
						case 19: // ncp: failure to converge on acceptable address
							disc_cause = TERM_SERVICE_UNAVAILABLE;
							disc_reason = (dir == 1)
								? "NCP: too many Configure-Naks received from peer"
								: "NCP: too many Configure-Naks sent to peer";
							break;
						case 20: // ncp: user not permitted to use any address
							disc_cause = TERM_SERVICE_UNAVAILABLE;
							disc_reason = (dir == 1)
								? "NCP: local link address not acceptable to peer"
								: "NCP: remote link address not acceptable";
							break;
						}
					}
					break;
				default:
					{
						static char e[] = "unknown AVP 0xXXXX";
						LOG(2, s, t, "   Unknown AVP type %u\n", mtype);
						fatal = flags;
						result = 2; // general error
						error = 8; // unknown mandatory AVP
						sprintf((msg = e) + 14, "%04x", mtype);
						continue; // next
					}
				}
			}
			// process message
			if (fatal & 0x80)
				tunnelshutdown(t, "Invalid mandatory AVP", result, error, msg);
			else
				switch (message)
				{
				case 1:       // SCCRQ - Start Control Connection Request
					tunnel[t].state = TUNNELOPENING;
					LOG(3, s, t, "Received SCCRQ\n");
					if (main_quit != QUIT_SHUTDOWN)
					{
						LOG(3, s, t, "sending SCCRP\n");
						controlt *c = controlnew(2); // sending SCCRP
						control16(c, 2, version, 1); // protocol version
						control32(c, 3, 3, 1); // framing
						controls(c, 7, config->multi_n_hostname[tunnel[t].indexudp][0]?config->multi_n_hostname[tunnel[t].indexudp]:hostname, 1); // host name
						if (sendchalresponse) controlb(c, 13, sendchalresponse, 16, 1); // Send Challenge response
						control16(c, 9, t, 1); // assigned tunnel
						controladd(c, 0, t); // send the resply
					}
					else
					{
						tunnelshutdown(t, "Shutting down", 6, 0, 0);
					}
					break;
				case 2:       // SCCRP
					tunnel[t].state = TUNNELOPEN;
					tunnel[t].lastrec = time_now;
					LOG(3, s, t, "Received SCCRP\n");
					if (main_quit != QUIT_SHUTDOWN)
					{
						if (tunnel[t].isremotelns && recvchalresponse)
						{
							hasht hash;

							lac_calc_rlns_auth(t, 2, hash); // id = 2 (SCCRP)
							// check authenticator
							if (memcmp(hash, recvchalresponse, 16) == 0)
							{
								LOG(3, s, t, "sending SCCCN to REMOTE LNS\n");
								controlt *c = controlnew(3); // sending SCCCN
								controls(c, 7, config->multi_n_hostname[tunnel[t].indexudp][0]?config->multi_n_hostname[tunnel[t].indexudp]:hostname, 1); // host name
								controls(c, 8, Vendor_name, 1); // Vendor name
								control16(c, 2, version, 1); // protocol version
								control32(c, 3, 3, 1); // framing Capabilities
								if (sendchalresponse) controlb(c, 13, sendchalresponse, 16, 1); // Challenge response
								control16(c, 9, t, 1); // assigned tunnel
								controladd(c, 0, t); // send
							}
							else
							{
								tunnelshutdown(t, "Bad chap response from REMOTE LNS", 4, 0, 0);
							}
						}
					}
					else
					{
						tunnelshutdown(t, "Shutting down", 6, 0, 0);
					}
					break;
				case 3:       // SCCN
					LOG(3, s, t, "Received SCCN\n");
					tunnel[t].state = TUNNELOPEN;
					tunnel[t].lastrec = time_now;
					controlnull(t); // ack
					break;
				case 4:       // StopCCN
					LOG(3, s, t, "Received StopCCN\n");
					controlnull(t); // ack
					tunnelshutdown(t, "Stopped", 0, 0, 0); // Shut down cleanly
					break;
				case 6:       // HELLO
					LOG(3, s, t, "Received HELLO\n");
					controlnull(t); // simply ACK
					break;
				case 7:       // OCRQ
					// TBA
					LOG(3, s, t, "Received OCRQ\n");
					break;
				case 8:       // OCRO
					// TBA
					LOG(3, s, t, "Received OCRO\n");
					break;
				case 9:       // OCCN
					// TBA
					LOG(3, s, t, "Received OCCN\n");
					break;
				case 10:      // ICRQ
					LOG(3, s, t, "Received ICRQ\n");
					if (sessionfree && main_quit != QUIT_SHUTDOWN)
					{
						controlt *c = controlnew(11); // ICRP

						LOG(3, s, t, "Sending ICRP\n");

						s = sessionfree;
						sessionfree = session[s].next;
						memset(&session[s], 0, sizeof(session[s]));

						if (s > config->cluster_highest_sessionid)
							config->cluster_highest_sessionid = s;

						session[s].opened = time_now;
						session[s].tunnel = t;
						session[s].far = asession;
						session[s].last_packet = session[s].last_data = time_now;
						LOG(3, s, t, "New session (%u/%u) - EKL\n", session[s].far, tunnel[t].far); // EKL - Consistency w/LOG
						//LOG(3, s, t, "New session (%u/%u)\n", tunnel[t].far, session[s].far);
						control16(c, 14, s, 1); // assigned session
						controladd(c, asession, t); // send the reply

						strncpy(session[s].called, called, sizeof(session[s].called) - 1);
						strncpy(session[s].calling, calling, sizeof(session[s].calling) - 1);

						session[s].ppp.phase = Establish;
						session[s].ppp.lcp = Starting;

						STAT(session_created);
						break;
					}

					{
						controlt *c = controlnew(14); // CDN
						LOG(3, s, t, "Sending CDN\n");
						if (!sessionfree)
						{
							STAT(session_overflow);
							LOG(1, 0, t, "No free sessions\n");
							control16(c, 1, 4, 0); // temporary lack of resources
						}
						else
							control16(c, 1, 2, 7); // shutting down, try another

						controladd(c, asession, t); // send the message
					}
					return;
				case 11:      // ICRP
				LOG(3, s, t, "Received ICRP\n");
				if (session[s].forwardtosession)
				{
					controlt *c = controlnew(12); // ICCN

					session[s].opened = time_now;
					session[s].tunnel = t;
					session[s].far = asession;
					session[s].last_packet = session[s].last_data = time_now;

					control32(c, 19, 1, 1); // Framing Type
					control32(c, 24, 10000000, 1); // Tx Connect Speed
					controladd(c, asession, t); // send the message
					LOG(3, s, t, "Sending ICCN\n");
				}
					break;
				case 12:      // ICCN
					LOG(3, s, t, "Received ICCN\n");
					if (amagic == 0) amagic = time_now;
					session[s].magic = amagic; // set magic number
					session[s].flags = aflags; // set flags received
					session[s].mru = PPPoE_MRU; // default
					controlnull(t); // ack

					// start LCP
					sess_local[s].lcp_authtype = config->radius_authprefer;
					sess_local[s].ppp_mru = MRU;

					// Set multilink options before sending initial LCP packet
					sess_local[s].mp_mrru = 1614;
					sess_local[s].mp_epdis = ntohl(config->iftun_address ? config->iftun_address : my_address);

					sendlcp(s, t);
					change_state(s, lcp, RequestSent);
					break;

				case 14:      // CDN
					LOG(3, s, t, "Received CDN\n");
					controlnull(t); // ack
					sessionshutdown(s, disc_reason, CDN_NONE, disc_cause);
					break;
				case 0xFFFF:
					LOG(1, s, t, "Missing message type\n");
					break;
				default:
					STAT(tunnel_rx_errors);
					if (mandatory)
						tunnelshutdown(t, "Unknown message type", 2, 6, "unknown message type");
					else
						LOG(1, s, t, "Unknown message type %u\n", message);
					break;
				}
			if (sendchalresponse) free(sendchalresponse);
			if (recvchalresponse) free(recvchalresponse);
			cluster_send_tunnel(t);
		}
		else
		{
			LOG(4, s, t, "   Got a ZLB ack\n");
		}
	}
	else
	{                          // data
		uint16_t proto;

		LOG_HEX(5, "Receive Tunnel Data", p, l);
		if (l > 2 && p[0] == 0xFF && p[1] == 0x03)
		{                     // HDLC address header, discard
			p += 2;
			l -= 2;
		}
		if (l < 2)
		{
			LOG(1, s, t, "Short ppp length %d\n", l);
			STAT(tunnel_rx_errors);
			return;
		}
		if (*p & 1)
		{
			proto = *p++;
			l--;
		}
		else
		{
			proto = ntohs(*(uint16_t *) p);
			p += 2;
			l -= 2;
		}

		if (session[s].forwardtosession)
		{
			LOG(5, s, t, "Forwarding data session to session %u\n", session[s].forwardtosession);
			// Forward to LAC/BAS or Remote LNS session
			lac_session_forward(buf, len, s, proto, addr->sin_addr.s_addr, addr->sin_port, indexudpfd);
			return;
		}
		else if (config->auth_tunnel_change_addr_src)
		{
			if (tunnel[t].ip != ntohl(addr->sin_addr.s_addr) &&
				tunnel[t].port == ntohs(addr->sin_port))
			{
				// The remotes BAS are a clustered l2tpns server and the source IP has changed
				LOG(5, s, t, "The tunnel IP source (%s) has changed by new IP (%s)\n",
					fmtaddr(htonl(tunnel[t].ip), 0), fmtaddr(addr->sin_addr.s_addr, 0));

				tunnel[t].ip = ntohl(addr->sin_addr.s_addr);
			}
		}

		if (s && !session[s].opened)	// Is something wrong??
		{
			if (!config->cluster_iam_master)
			{
				// Pass it off to the master to deal with..
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd);
				return;
			}

			LOG(1, s, t, "UDP packet contains session which is not opened.  Dropping packet.\n");
			STAT(tunnel_rx_errors);
			return;
		}

		if (proto == PPPPAP)
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd); return; }
			processpap(s, t, p, l);
		}
		else if (proto == PPPCHAP)
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd); return; }
			processchap(s, t, p, l);
		}
		else if (proto == PPPLCP)
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd); return; }
			processlcp(s, t, p, l);
		}
		else if (proto == PPPIPCP)
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd); return; }
			processipcp(s, t, p, l);
		}
		else if (proto == PPPIPV6CP && config->ipv6_prefix.s6_addr[0])
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd); return; }
			processipv6cp(s, t, p, l);
		}
		else if (proto == PPPCCP)
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd); return; }
			processccp(s, t, p, l);
		}
		else if (proto == PPPIP)
		{
			if (session[s].die)
			{
				LOG(4, s, t, "Session %u is closing.  Don't process PPP packets\n", s);
				return;              // closing session, PPP not processed
			}

			session[s].last_packet = session[s].last_data = time_now;
			if (session[s].walled_garden && !config->cluster_iam_master)
			{
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd);
				return;
			}

			processipin(s, t, p, l);
		}
		else if (proto == PPPMP)
		{
			if (session[s].die)
			{
				LOG(4, s, t, "Session %u is closing.  Don't process PPP packets\n", s);
				return;              // closing session, PPP not processed
			}

			session[s].last_packet = session[s].last_data = time_now;
			if (!config->cluster_iam_master)
			{
				// The fragments reconstruction is managed by the Master.
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd);
				return;
			}

			processmpin(s, t, p, l);
		}
		else if (proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0])
		{
			if (session[s].die)
			{
				LOG(4, s, t, "Session %u is closing.  Don't process PPP packets\n", s);
				return;              // closing session, PPP not processed
			}

			session[s].last_packet = session[s].last_data = time_now;
			if (session[s].walled_garden && !config->cluster_iam_master)
			{
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd);
				return;
			}

			if (!config->cluster_iam_master)
			{
				// Check if DhcpV6, IP dst: FF02::1:2, Src Port 0x0222 (546), Dst Port 0x0223 (547)
				if (*(p + 6) == 17 && *(p + 24) == 0xFF && *(p + 25) == 2 &&
						*(uint32_t *)(p + 26) == 0 && *(uint32_t *)(p + 30) == 0 &&
						*(uint16_t *)(p + 34) == 0 && *(p + 36) == 0 && *(p + 37) == 1 && *(p + 38) == 0 && *(p + 39) == 2 &&
						*(p + 40) == 2 && *(p + 41) == 0x22 && *(p + 42) == 2 && *(p + 43) == 0x23)
				{
					// DHCPV6 must be managed by the Master.
					master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd);
					return;
				}
			}

			processipv6in(s, t, p, l);
		}
		else if (session[s].ppp.lcp == Opened)
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port, indexudpfd); return; }
			protoreject(s, t, p, l, proto);
		}
		else
		{
			LOG(2, s, t, "Unknown PPP protocol 0x%04X received in LCP %s state\n",
				proto, ppp_state(session[s].ppp.lcp));
		}
	}
}

// read and process packet on tun
// (i.e. this routine writes to buf[-8]).
static void processtun(uint8_t * buf, int len)
{
	LOG_HEX(5, "Receive TUN Data", buf, len);
	STAT(tun_rx_packets);
	INC_STAT(tun_rx_bytes, len);

	CSTAT(processtun);

	eth_rx_pkt++;
	eth_rx += len;
	if (len < 22)
	{
		LOG(1, 0, 0, "Short tun packet %d bytes\n", len);
		STAT(tun_rx_errors);
		return;
	}

	if (*(uint16_t *) (buf + 2) == htons(PKTIP)) // IPv4
		processipout(buf, len);
	else if (*(uint16_t *) (buf + 2) == htons(PKTIPV6) // IPV6
	    && config->ipv6_prefix.s6_addr[0])
		processipv6out(buf, len);

	// Else discard.
}

// Handle retries, timeouts.  Runs every 1/10th sec, want to ensure
// that we look at the whole of the tunnel, radius and session tables
// every second
static void regular_cleanups(double period)
{
	// Next tunnel, radius and session to check for actions on.
	static tunnelidt t = 0;
	static int r = 0;
	static sessionidt s = 0;

	int t_actions = 0;
	int r_actions = 0;
	int s_actions = 0;

	int t_slice;
	int r_slice;
	int s_slice;

	int i;
	int a;

	// divide up tables into slices based on the last run
	t_slice = config->cluster_highest_tunnelid  * period;
	r_slice = (MAXRADIUS - 1)                   * period;
	s_slice = config->cluster_highest_sessionid * period;

	if (t_slice < 1)
	    t_slice = 1;
	else if (t_slice > config->cluster_highest_tunnelid)
	    t_slice = config->cluster_highest_tunnelid;

	if (r_slice < 1)
	    r_slice = 1;
	else if (r_slice > (MAXRADIUS - 1))
	    r_slice = MAXRADIUS - 1;

	if (s_slice < 1)
	    s_slice = 1;
	else if (s_slice > config->cluster_highest_sessionid)
	    s_slice = config->cluster_highest_sessionid;

	LOG(4, 0, 0, "Begin regular cleanup (last %f seconds ago)\n", period);

	for (i = 0; i < t_slice; i++)
	{
		t++;
		if (t > config->cluster_highest_tunnelid)
			t = 1;

		if (t == TUNNEL_ID_PPPOE)
			continue;

		// check for expired tunnels
		if (tunnel[t].die && tunnel[t].die <= TIME)
		{
			STAT(tunnel_timeout);
			tunnelkill(t, "Expired");
			t_actions++;
			continue;
		}
		// check for message resend
		if (tunnel[t].retry && tunnel[t].controlc)
		{
			// resend pending messages as timeout on reply
			if (tunnel[t].retry <= TIME)
			{
				controlt *c = tunnel[t].controls;
				uint16_t w = tunnel[t].window;
				tunnel[t].try++; // another try
				if (tunnel[t].try > 5)
					tunnelkill(t, "Timeout on control message"); // game over
				else
					while (c && w--)
					{
						tunnelsend(c->buf, c->length, t);
						c = c->next;
					}

				t_actions++;
			}
		}
		// Send hello
		if (tunnel[t].state == TUNNELOPEN && !tunnel[t].controlc && (time_now - tunnel[t].lastrec) > 60)
		{
			if (!config->disable_sending_hello)
			{
				controlt *c = controlnew(6); // sending HELLO
				controladd(c, 0, t); // send the message
				LOG(3, 0, t, "Sending HELLO message\n");
				t_actions++;
			}
		}

		// Check for tunnel changes requested from the CLI
		if ((a = cli_tunnel_actions[t].action))
		{
			cli_tunnel_actions[t].action = 0;
			if (a & CLI_TUN_KILL)
			{
				LOG(2, 0, t, "Dropping tunnel by CLI\n");
				tunnelshutdown(t, "Requested by administrator", 1, 0, 0);
				t_actions++;
			}
		}
	}

	for (i = 0; i < r_slice; i++)
	{
		r++;
		if (r >= MAXRADIUS)
			r = 1;

		if (!radius[r].state)
			continue;

		if (radius[r].retry <= TIME)
		{
			radiusretry(r);
			r_actions++;
		}
	}

	for (i = 0; i < s_slice; i++)
	{
		s++;
		if (s > config->cluster_highest_sessionid)
			s = 1;

		if (!session[s].opened)	// Session isn't in use
			continue;

		// check for expired sessions
		if (session[s].die)
		{
			if (session[s].die <= TIME)
			{
				sessionkill(s, "Expired");
				s_actions++;
			}
			continue;
		}

		// PPP timeouts
		if (sess_local[s].lcp.restart <= time_now)
		{
			int next_state = session[s].ppp.lcp;
			switch (session[s].ppp.lcp)
			{
			case RequestSent:
			case AckReceived:
			    	next_state = RequestSent;

			case AckSent:
				if (sess_local[s].lcp.conf_sent < config->ppp_max_configure)
				{
					LOG(3, s, session[s].tunnel, "No ACK for LCP ConfigReq... resending\n");
					sendlcp(s, session[s].tunnel);
					change_state(s, lcp, next_state);
				}
				else
				{
					sessionshutdown(s, "No response to LCP ConfigReq.", CDN_ADMIN_DISC, TERM_LOST_SERVICE);
					STAT(session_timeout);
				}

				s_actions++;
			}

			if (session[s].die)
				continue;
		}

		if (sess_local[s].ipcp.restart <= time_now)
		{
			int next_state = session[s].ppp.ipcp;
			switch (session[s].ppp.ipcp)
			{
			case RequestSent:
			case AckReceived:
			    	next_state = RequestSent;

			case AckSent:
				if (sess_local[s].ipcp.conf_sent < config->ppp_max_configure)
				{
					LOG(3, s, session[s].tunnel, "No ACK for IPCP ConfigReq... resending\n");
					sendipcp(s, session[s].tunnel);
					change_state(s, ipcp, next_state);
				}
				else
				{
					sessionshutdown(s, "No response to IPCP ConfigReq.", CDN_ADMIN_DISC, TERM_LOST_SERVICE);
					STAT(session_timeout);
				}

				s_actions++;
			}

			if (session[s].die)
				continue;
		}

		if (sess_local[s].ipv6cp.restart <= time_now)
		{
			int next_state = session[s].ppp.ipv6cp;
			switch (session[s].ppp.ipv6cp)
			{
			case RequestSent:
			case AckReceived:
			    	next_state = RequestSent;

			case AckSent:
				if (sess_local[s].ipv6cp.conf_sent < config->ppp_max_configure)
				{
					LOG(3, s, session[s].tunnel, "No ACK for IPV6CP ConfigReq... resending\n");
					sendipv6cp(s, session[s].tunnel);
					change_state(s, ipv6cp, next_state);
				}
				else
				{
					LOG(3, s, session[s].tunnel, "No ACK for IPV6CP ConfigReq\n");
					change_state(s, ipv6cp, Stopped);
				}

				s_actions++;
			}
		}

		if (sess_local[s].ccp.restart <= time_now)
		{
			int next_state = session[s].ppp.ccp;
			switch (session[s].ppp.ccp)
			{
			case RequestSent:
			case AckReceived:
			    	next_state = RequestSent;

			case AckSent:
				if (sess_local[s].ccp.conf_sent < config->ppp_max_configure)
				{
					LOG(3, s, session[s].tunnel, "No ACK for CCP ConfigReq... resending\n");
					sendccp(s, session[s].tunnel);
					change_state(s, ccp, next_state);
				}
				else
				{
					LOG(3, s, session[s].tunnel, "No ACK for CCP ConfigReq\n");
					change_state(s, ccp, Stopped);
				}

				s_actions++;
			}
		}

		// Drop sessions who have not responded within IDLE_ECHO_TIMEOUT seconds
		if (session[s].last_packet && (time_now - session[s].last_packet >= config->idle_echo_timeout))
		{
			sessionshutdown(s, "No response to LCP ECHO requests.", CDN_ADMIN_DISC, TERM_LOST_SERVICE);
			STAT(session_timeout);
			s_actions++;
			continue;
		}

		// No data in ECHO_TIMEOUT seconds, send LCP ECHO
		if (session[s].ppp.phase >= Establish && (time_now - session[s].last_packet >= config->echo_timeout) &&
			(time_now - sess_local[s].last_echo >= ECHO_TIMEOUT))
		{
			uint8_t b[MAXETHER];

			uint8_t *q = makeppp(b, sizeof(b), 0, 0, s, session[s].tunnel, PPPLCP, 1, 0, 0);
			if (!q) continue;

			*q = EchoReq;
			*(uint8_t *)(q + 1) = (time_now % 255); // ID
			*(uint16_t *)(q + 2) = htons(8); // Length
			*(uint32_t *)(q + 4) = session[s].ppp.lcp == Opened ? htonl(session[s].magic) : 0; // Magic Number

			LOG(4, s, session[s].tunnel, "No data in %d seconds, sending LCP ECHO\n",
					(int)(time_now - session[s].last_packet));

			tunnelsend(b, (q - b) + 8, session[s].tunnel); // send it
			sess_local[s].last_echo = time_now;
			s_actions++;
		}

		// Drop sessions who have reached session_timeout seconds
		if (session[s].session_timeout)
		{
			bundleidt bid = session[s].bundle;
			if (bid)
			{
				if (time_now - bundle[bid].last_check >= 1)
				{
					bundle[bid].online_time += (time_now - bundle[bid].last_check) * bundle[bid].num_of_links;
					bundle[bid].last_check = time_now;
					if (bundle[bid].online_time >= session[s].session_timeout)
					{
						int ses;
						for (ses = bundle[bid].num_of_links - 1; ses >= 0; ses--)
						{
							sessionshutdown(bundle[bid].members[ses], "Session timeout", CDN_ADMIN_DISC, TERM_SESSION_TIMEOUT);
							s_actions++;
							continue;
						}
					}
				}
			}
			else if (time_now - session[s].opened >= session[s].session_timeout)
			{
				sessionshutdown(s, "Session timeout", CDN_ADMIN_DISC, TERM_SESSION_TIMEOUT);
				s_actions++;
				continue;
			}
		}

		// Drop sessions who have reached idle_timeout seconds
		if (session[s].last_data && session[s].idle_timeout && (time_now - session[s].last_data >= session[s].idle_timeout))
		{
			sessionshutdown(s, "Idle Timeout Reached", CDN_ADMIN_DISC, TERM_IDLE_TIMEOUT);
			STAT(session_timeout);
			s_actions++;
			continue;
		}

		// Check for actions requested from the CLI
		if ((a = cli_session_actions[s].action))
		{
			int send = 0;

			cli_session_actions[s].action = 0;
			if (a & CLI_SESS_KILL)
			{
				LOG(2, s, session[s].tunnel, "Dropping session by CLI\n");
				sessionshutdown(s, "Requested by administrator.", CDN_ADMIN_DISC, TERM_ADMIN_RESET);
				a = 0; // dead, no need to check for other actions
				s_actions++;
			}

			if (a & CLI_SESS_NOSNOOP)
			{
				LOG(2, s, session[s].tunnel, "Unsnooping session by CLI\n");
				session[s].snoop_ip = 0;
				session[s].snoop_port = 0;
				s_actions++;
				send++;
			}
			else if (a & CLI_SESS_SNOOP)
			{
				LOG(2, s, session[s].tunnel, "Snooping session by CLI (to %s:%u)\n",
				    fmtaddr(cli_session_actions[s].snoop_ip, 0),
				    cli_session_actions[s].snoop_port);

				session[s].snoop_ip = cli_session_actions[s].snoop_ip;
				session[s].snoop_port = cli_session_actions[s].snoop_port;
				s_actions++;
				send++;
			}

			if (a & CLI_SESS_NOTHROTTLE)
			{
				LOG(2, s, session[s].tunnel, "Un-throttling session by CLI\n");
				throttle_session(s, 0, 0);
				s_actions++;
				send++;
			}
			else if (a & CLI_SESS_THROTTLE)
			{
				LOG(2, s, session[s].tunnel, "Throttling session by CLI (to %dkb/s up and %dkb/s down)\n",
				    cli_session_actions[s].throttle_in,
				    cli_session_actions[s].throttle_out);

				throttle_session(s, cli_session_actions[s].throttle_in, cli_session_actions[s].throttle_out);
				s_actions++;
				send++;
			}

			if (a & CLI_SESS_NOFILTER)
			{
				LOG(2, s, session[s].tunnel, "Un-filtering session by CLI\n");
				filter_session(s, 0, 0);
				s_actions++;
				send++;
			}
			else if (a & CLI_SESS_FILTER)
			{
				LOG(2, s, session[s].tunnel, "Filtering session by CLI (in=%d, out=%d)\n",
				    cli_session_actions[s].filter_in,
				    cli_session_actions[s].filter_out);

				filter_session(s, cli_session_actions[s].filter_in, cli_session_actions[s].filter_out);
				s_actions++;
				send++;
			}

			if (send)
				cluster_send_session(s);
		}

		// RADIUS interim accounting
		if (config->radius_accounting && config->radius_interim > 0
		    && session[s].ip && !session[s].walled_garden
		    && !sess_local[s].radius // RADIUS already in progress
		    && time_now - sess_local[s].last_interim >= config->radius_interim
		    && session[s].flags & SESSION_STARTED)
		{
		    	int rad = radiusnew(s);
			if (!rad)
			{
				LOG(1, s, session[s].tunnel, "No free RADIUS sessions for Interim message\n");
				STAT(radius_overflow);
				continue;
			}

			LOG(3, s, session[s].tunnel, "Sending RADIUS Interim for %s (%u)\n",
				session[s].user, session[s].unique_id);

			radiussend(rad, RADIUSINTERIM);
			sess_local[s].last_interim = time_now;
			s_actions++;
		}
	}

	LOG(4, 0, 0, "End regular cleanup: checked %d/%d/%d tunnels/radius/sessions; %d/%d/%d actions\n",
		t_slice, r_slice, s_slice, t_actions, r_actions, s_actions);
}

//
// Are we in the middle of a tunnel update, or radius
// requests??
//
static int still_busy(void)
{
	int i;
	static clockt last_talked = 0;
	static clockt start_busy_wait = 0;

#ifdef BGP
	static time_t stopped_bgp = 0;
	if (bgp_configured)
	{
		if (!stopped_bgp)
		{
			LOG(1, 0, 0, "Shutting down in %d seconds, stopping BGP...\n", QUIT_DELAY);

			for (i = 0; i < BGP_NUM_PEERS; i++)
				if (bgp_peers[i].state == Established)
					bgp_stop(&bgp_peers[i]);

			stopped_bgp = time_now;

			if (!config->cluster_iam_master)
			{
				// we don't want to become master
				cluster_send_ping(0);

				return 1;
			}
		}

		if (!config->cluster_iam_master && time_now < (stopped_bgp + QUIT_DELAY))
			return 1;
	}
#endif /* BGP */

	if (!config->cluster_iam_master)
		return 0;

	if (main_quit == QUIT_SHUTDOWN)
	{
		static int dropped = 0;
		if (!dropped)
		{
		    	int i;

			LOG(1, 0, 0, "Dropping sessions and tunnels\n");
			for (i = 1; i < MAXTUNNEL; i++)
				if (tunnel[i].ip || tunnel[i].state)
					tunnelshutdown(i, "L2TPNS Closing", 6, 0, 0);

			dropped = 1;
		}
	}

	if (start_busy_wait == 0)
		start_busy_wait = TIME;

	for (i = config->cluster_highest_tunnelid ; i > 0 ; --i)
	{
		if (!tunnel[i].controlc)
			continue;

		if (last_talked != TIME)
		{
			LOG(2, 0, 0, "Tunnel %u still has un-acked control messages.\n", i);
			last_talked = TIME;
		}
		return 1;
	}

	// We stop waiting for radius after BUSY_WAIT_TIME 1/10th seconds
	if (abs(TIME - start_busy_wait) > BUSY_WAIT_TIME)
	{
		LOG(1, 0, 0, "Giving up waiting for RADIUS to be empty.  Shutting down anyway.\n");
		return 0;
	}

	for (i = 1; i < MAXRADIUS; i++)
	{
		if (radius[i].state == RADIUSNULL)
			continue;
	        if (radius[i].state == RADIUSWAIT)
			continue;

		if (last_talked != TIME)
		{
			LOG(2, 0, 0, "Radius session %u is still busy (sid %u)\n", i, radius[i].session);
			last_talked = TIME;
		}
		return 1;
	}

	return 0;
}

#ifdef HAVE_EPOLL
# include <sys/epoll.h>
#else
# define FAKE_EPOLL_IMPLEMENTATION /* include the functions */
# include "fake_epoll.h"
#endif

// the base set of fds polled: cli, cluster, tun, udp (MAX_UDPFD), control, dae, netlink, udplac, pppoedisc, pppoesess
#define BASE_FDS	(9 + MAX_UDPFD)

// additional polled fds
#ifdef BGP
# define EXTRA_FDS	BGP_NUM_PEERS
#else
# define EXTRA_FDS	0
#endif

// main loop - gets packets on tun or udp and processes them
static void mainloop(void)
{
	int i, j;
	uint8_t buf[65536];
	uint8_t *p = buf + 32; // for the hearder of the forwarded MPPP packet (see C_MPPP_FORWARD)
						// and the forwarded pppoe session
	int size_bufp = sizeof(buf) - 32;
	clockt next_cluster_ping = 0;	// send initial ping immediately
	struct epoll_event events[BASE_FDS + RADIUS_FDS + EXTRA_FDS];
	int maxevent = sizeof(events)/sizeof(*events);

	if ((epollfd = epoll_create(maxevent)) < 0)
	{
	    	LOG(0, 0, 0, "epoll_create failed: %s\n", strerror(errno));
		exit(1);
	}

	LOG(4, 0, 0, "Beginning of main loop.  clifd=%d, cluster_sockfd=%d, tunfd=%d, udpfd=%d, controlfd=%d, daefd=%d, nlfd=%d , udplacfd=%d, pppoefd=%d, pppoesessfd=%d\n",
		clifd, cluster_sockfd, tunfd, udpfd[0], controlfd, daefd, nlfd, udplacfd, pppoediscfd, pppoesessfd);

	/* setup our fds to poll for input */
	{
		static struct event_data d[BASE_FDS];
		struct epoll_event e;

		e.events = EPOLLIN;
		i = 0;

		if (clifd >= 0)
		{
			d[i].type = FD_TYPE_CLI;
			e.data.ptr = &d[i++];
			epoll_ctl(epollfd, EPOLL_CTL_ADD, clifd, &e);
		}

		d[i].type = FD_TYPE_CLUSTER;
		e.data.ptr = &d[i++];
		epoll_ctl(epollfd, EPOLL_CTL_ADD, cluster_sockfd, &e);

		d[i].type = FD_TYPE_TUN;
		e.data.ptr = &d[i++];
		epoll_ctl(epollfd, EPOLL_CTL_ADD, tunfd, &e);

		d[i].type = FD_TYPE_CONTROL;
		e.data.ptr = &d[i++];
		epoll_ctl(epollfd, EPOLL_CTL_ADD, controlfd, &e);

		d[i].type = FD_TYPE_DAE;
		e.data.ptr = &d[i++];
		epoll_ctl(epollfd, EPOLL_CTL_ADD, daefd, &e);

		d[i].type = FD_TYPE_NETLINK;
		e.data.ptr = &d[i++];
		epoll_ctl(epollfd, EPOLL_CTL_ADD, nlfd, &e);

		d[i].type = FD_TYPE_PPPOEDISC;
		e.data.ptr = &d[i++];
		epoll_ctl(epollfd, EPOLL_CTL_ADD, pppoediscfd, &e);

		d[i].type = FD_TYPE_PPPOESESS;
		e.data.ptr = &d[i++];
		epoll_ctl(epollfd, EPOLL_CTL_ADD, pppoesessfd, &e);

		for (j = 0; j < config->nbudpfd; j++)
		{
			d[i].type = FD_TYPE_UDP;
			d[i].index = j;
			e.data.ptr = &d[i++];
			epoll_ctl(epollfd, EPOLL_CTL_ADD, udpfd[j], &e);
		}
	}

#ifdef BGP
	signal(SIGPIPE, SIG_IGN);
	bgp_setup(config->as_number);
	if (config->bind_address)
		bgp_add_route(config->bind_address, 0xffffffff);

	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
		if (config->neighbour[i].name[0])
			bgp_start(&bgp_peers[i], config->neighbour[i].name,
				config->neighbour[i].as, config->neighbour[i].keepalive,
				config->neighbour[i].hold, config->neighbour[i].update_source,
				0); /* 0 = routing disabled */
	}
#endif /* BGP */

	while (!main_quit || still_busy())
	{
		int more = 0;
		int n;


		if (main_reload)
		{
			main_reload = 0;
			read_config_file();
			config->reload_config++;
		}

		if (config->reload_config)
		{
			config->reload_config = 0;
			update_config();
		}

#ifdef BGP
		bgp_set_poll();
#endif /* BGP */

		n = epoll_wait(epollfd, events, maxevent, 100); // timeout 100ms (1/10th sec)
		STAT(select_called);

		TIME = now(NULL);
		if (n < 0)
		{
			if (errno == EINTR ||
			    errno == ECHILD) // EINTR was clobbered by sigchild_handler()
				continue;

			LOG(0, 0, 0, "Error returned from select(): %s\n", strerror(errno));
			break; // exit
		}

		if (n)
		{
			struct sockaddr_in addr;
			struct in_addr local;
			socklen_t alen;
			int c, s;
			int udp_ready[MAX_UDPFD + 1] = INIT_TABUDPVAR;
			int pppoesess_ready = 0;
			int pppoesess_pkts = 0;
			int tun_ready = 0;
			int cluster_ready = 0;
			int udp_pkts[MAX_UDPFD + 1] = INIT_TABUDPVAR;
			int tun_pkts = 0;
			int cluster_pkts = 0;
#ifdef BGP
			uint32_t bgp_events[BGP_NUM_PEERS];
			memset(bgp_events, 0, sizeof(bgp_events));
#endif /* BGP */

			for (c = n, i = 0; i < c; i++)
			{
				struct event_data *d = events[i].data.ptr;

				switch (d->type)
				{
				case FD_TYPE_CLI: // CLI connections
				{
					int cli;
					
					alen = sizeof(addr);
					if ((cli = accept(clifd, (struct sockaddr *)&addr, &alen)) >= 0)
					{
						cli_do(cli);
						close(cli);
					}
					else
						LOG(0, 0, 0, "accept error: %s\n", strerror(errno));

					n--;
					break;
				}

				// these are handled below, with multiple interleaved reads
				case FD_TYPE_CLUSTER:	cluster_ready++; break;
				case FD_TYPE_TUN:	tun_ready++; break;
				case FD_TYPE_UDP:	udp_ready[d->index]++; break;
				case FD_TYPE_PPPOESESS:	pppoesess_ready++; break;

				case FD_TYPE_PPPOEDISC: // pppoe discovery
					s = read(pppoediscfd, p, size_bufp);
					if (s > 0) process_pppoe_disc(p, s);
					n--;
					break;

				case FD_TYPE_CONTROL: // nsctl commands
					alen = sizeof(addr);
					s = recvfromto(controlfd, p, size_bufp, MSG_WAITALL, (struct sockaddr *) &addr, &alen, &local);
					if (s > 0) processcontrol(p, s, &addr, alen, &local);
					n--;
					break;

				case FD_TYPE_DAE: // DAE requests
					alen = sizeof(addr);
					s = recvfromto(daefd, p, size_bufp, MSG_WAITALL, (struct sockaddr *) &addr, &alen, &local);
					if (s > 0) processdae(p, s, &addr, alen, &local);
					n--;
					break;

				case FD_TYPE_RADIUS: // RADIUS response
					alen = sizeof(addr);
					s = recvfrom(radfds[d->index], p, size_bufp, MSG_WAITALL, (struct sockaddr *) &addr, &alen);
					if (s >= 0 && config->cluster_iam_master)
					{
						if (addr.sin_addr.s_addr == config->radiusserver[0] ||
						    addr.sin_addr.s_addr == config->radiusserver[1])
							processrad(p, s, d->index);
						else
							LOG(3, 0, 0, "Dropping RADIUS packet from unknown source %s\n",
								fmtaddr(addr.sin_addr.s_addr, 0));
					}

					n--;
					break;

#ifdef BGP
				case FD_TYPE_BGP:
					bgp_events[d->index] = events[i].events;
					n--;
					break;
#endif /* BGP */

				case FD_TYPE_NETLINK:
				{
					struct nlmsghdr *nh = (struct nlmsghdr *)p;
					s = netlink_recv(p, size_bufp);
					if (nh->nlmsg_type == NLMSG_ERROR)
					{
						struct nlmsgerr *errmsg = NLMSG_DATA(nh);
						if (errmsg->error)
						{
							if (errmsg->msg.nlmsg_seq < min_initok_nlseqnum)
							{
								LOG(0, 0, 0, "Got a fatal netlink error (while %s): %s\n", tun_nl_phase_msg[nh->nlmsg_seq], strerror(-errmsg->error));
								exit(1);
							}
							else
								LOG(0, 0, 0, "Got a netlink error: %s\n", strerror(-errmsg->error));
						}
						// else it's a ack
					}
					else
						LOG(1, 0, 0, "Got a unknown netlink message: type %d seq %d flags %d\n", nh->nlmsg_type, nh->nlmsg_seq, nh->nlmsg_flags);
					n--;
					break;
				}

				default:
					LOG(0, 0, 0, "Unexpected fd type returned from epoll_wait: %d\n", d->type);
				}
			}

#ifdef BGP
			bgp_process(bgp_events);
#endif /* BGP */

			for (c = 0; n && c < config->multi_read_count; c++)
			{
				for (j = 0; j < config->nbudpfd; j++)
				{
					// L2TP and L2TP REMOTE LNS
					if (udp_ready[j])
					{
						alen = sizeof(addr);
						if ((s = recvfrom(udpfd[j], p, size_bufp, 0, (void *) &addr, &alen)) > 0)
						{
							processudp(p, s, &addr, j);
							udp_pkts[j]++;
						}
						else
						{
							udp_ready[j] = 0;
							n--;
						}
					}
				}

				// incoming IP
				if (tun_ready)
				{
					if ((s = read(tunfd, p, size_bufp)) > 0)
					{
						processtun(p, s);
						tun_pkts++;
					}
					else
					{
						tun_ready = 0;
						n--;
					}
				}

				// pppoe session
				if (pppoesess_ready)
				{
					if ((s = read(pppoesessfd, p, size_bufp)) > 0)
					{
						process_pppoe_sess(p, s);
						pppoesess_pkts++;
					}
					else
					{
						pppoesess_ready = 0;
						n--;
					}
				}

				// cluster
				if (cluster_ready)
				{
					alen = sizeof(addr);
					if ((s = recvfrom(cluster_sockfd, p, size_bufp, MSG_WAITALL, (void *) &addr, &alen)) > 0)
					{
						processcluster(p, s, addr.sin_addr.s_addr);
						cluster_pkts++;
					}
					else
					{
						cluster_ready = 0;
						n--;
					}
				}
			}

			if (udp_pkts[0] > 1 || tun_pkts > 1 || cluster_pkts > 1)
				STAT(multi_read_used);

			if (c >= config->multi_read_count)
			{
				LOG(3, 0, 0, "Reached multi_read_count (%d); processed %d udp, %d tun %d cluster and %d pppoe packets\n",
					config->multi_read_count, udp_pkts[0], tun_pkts, cluster_pkts, pppoesess_pkts);
				STAT(multi_read_exceeded);
				more++;
			}
		}
#ifdef BGP
		else
			/* no event received, but timers could still have expired */
			bgp_process_peers_timers();
#endif /* BGP */

		if (time_changed)
		{
			double Mbps = 1024.0 * 1024.0 / 8 * time_changed;

			// Log current traffic stats
			snprintf(config->bandwidth, sizeof(config->bandwidth),
				"UDP-ETH:%1.0f/%1.0f  ETH-UDP:%1.0f/%1.0f  TOTAL:%0.1f   IN:%u OUT:%u",
				(udp_rx / Mbps), (eth_tx / Mbps), (eth_rx / Mbps), (udp_tx / Mbps),
				((udp_tx + udp_rx + eth_tx + eth_rx) / Mbps),
				udp_rx_pkt / time_changed, eth_rx_pkt / time_changed);
		 
			udp_tx = udp_rx = 0;
			udp_rx_pkt = eth_rx_pkt = 0;
			eth_tx = eth_rx = 0;
			time_changed = 0;
		 
			if (config->dump_speed)
				printf("%s\n", config->bandwidth);
		 
			// Update the internal time counter
			strftime(time_now_string, sizeof(time_now_string), "%Y-%m-%d %H:%M:%S", localtime(&time_now));
		 
			{
				// Run timer hooks
				struct param_timer p = { time_now };
				run_plugins(PLUGIN_TIMER, &p);
			}
		}

			// Runs on every machine (master and slaves).
		if (next_cluster_ping <= TIME)
		{
			// Check to see which of the cluster is still alive..

			cluster_send_ping(basetime);	// Only does anything if we're a slave
			cluster_check_master();		// ditto.

			cluster_heartbeat();		// Only does anything if we're a master.
			cluster_check_slaves();		// ditto.

			master_update_counts();		// If we're a slave, send our byte counters to our master.

			if (config->cluster_iam_master && !config->cluster_iam_uptodate)
				next_cluster_ping = TIME + 1; // out-of-date slaves, do fast updates
			else
				next_cluster_ping = TIME + config->cluster_hb_interval;
		}

		if (!config->cluster_iam_master)
			continue;

			// Run token bucket filtering queue..
			// Only run it every 1/10th of a second.
		{
			static clockt last_run = 0;
			if (last_run != TIME)
			{
				last_run = TIME;
				tbf_run_timer();
			}
		}

			// Handle timeouts, retries etc.
		{
			static double last_clean = 0;
			double this_clean;
			double diff;

			TIME = now(&this_clean);
			diff = this_clean - last_clean;

			// Run during idle time (after we've handled
			// all incoming packets) or every 1/10th sec
			if (!more || diff > 0.1)
			{
				regular_cleanups(diff);
				last_clean = this_clean;
			}
		}

		if (*config->accounting_dir)
		{
			static clockt next_acct = 0;
			static clockt next_shut_acct = 0;

			if (next_acct <= TIME)
			{
				// Dump accounting data
				next_acct = TIME + ACCT_TIME;
				next_shut_acct = TIME + ACCT_SHUT_TIME;
				dump_acct_info(1);
			}
			else if (next_shut_acct <= TIME)
			{
				// Dump accounting data for shutdown sessions
				next_shut_acct = TIME + ACCT_SHUT_TIME;
				if (shut_acct_n)
					dump_acct_info(0);
			}
		}
	}

		// Are we the master and shutting down??
	if (config->cluster_iam_master)
		cluster_heartbeat(); // Flush any queued changes..

		// Ok. Notify everyone we're shutting down. If we're
		// the master, this will force an election.
	cluster_send_ping(0);

	//
	// Important!!! We MUST not process any packets past this point!
	LOG(1, 0, 0, "Shutdown complete\n");
}

static void stripdomain(char *host)
{
	char *p;

	if ((p = strchr(host, '.')))
	{
		char *domain = 0;
		char _domain[1024];

		// strip off domain
		FILE *resolv = fopen("/etc/resolv.conf", "r");
		if (resolv)
		{
			char buf[1024];
			char *b;

			while (fgets(buf, sizeof(buf), resolv))
			{
				if (strncmp(buf, "domain", 6) && strncmp(buf, "search", 6))
					continue;

				if (!isspace(buf[6]))
					continue;

				b = buf + 7;
				while (isspace(*b)) b++;

				if (*b)
				{
					char *d = b;
					while (*b && !isspace(*b)) b++;
					*b = 0;
					if (buf[0] == 'd') // domain is canonical
					{
						domain = d;
						break;
					}

					// first search line
					if (!domain)
					{
						// hold, may be subsequent domain line
						strncpy(_domain, d, sizeof(_domain))[sizeof(_domain)-1] = 0;
						domain = _domain;
					}
				}
			}

			fclose(resolv);
		}

		if (domain)
		{
			int hl = strlen(host);
			int dl = strlen(domain);
			if (dl < hl && host[hl - dl - 1] == '.' && !strcmp(host + hl - dl, domain))
				host[hl -dl - 1] = 0;
		}
		else
		{
			*p = 0; // everything after first dot
		}
	}
}

static void malloc_pool(uint16_t x) {
	if (!(ip_address_pool[x] = shared_malloc(sizeof(ippoolt) * MAXIPPOOL)))
	{
		LOG(0, 0, 0, "Error doing malloc for pool %d ip_address_pool: %s\n", 
                    (x || ' '),
                    strerror(errno));
		exit(1);
	}
        ip_pool_size[x] = 1;
}

// Init data structures
static void initdata(int optdebug, char *optconfig)
{
	int i;

	if (!(config = shared_malloc(sizeof(configt))))
	{
		fprintf(stderr, "Error doing malloc for configuration: %s\n", strerror(errno));
		exit(1);
	}

	memset(config, 0, sizeof(configt));
	time(&config->start_time);
	strncpy(config->config_file, optconfig, strlen(optconfig));
	config->debug = optdebug;
	config->num_tbfs = MAXTBFS;
	config->rl_rate = 28; // 28kbps
	config->cluster_mcast_ttl = 1;
 	config->cluster_master_min_adv = 1;
	config->ppp_restart_time = 3;
	config->ppp_max_configure = 10;
	config->ppp_max_failure = 5;
	config->kill_timedout_sessions = 1;
	strcpy(config->random_device, RANDOMDEVICE);
	// Set default value echo_timeout and idle_echo_timeout
	config->echo_timeout = ECHO_TIMEOUT;
	config->idle_echo_timeout = IDLE_ECHO_TIMEOUT;
	// Set default RDNSS lifetime
	config->dns6_lifetime = 1200;

	log_stream = stderr;

#ifdef RINGBUFFER
	if (!(ringbuffer = shared_malloc(sizeof(struct Tringbuffer))))
	{
		LOG(0, 0, 0, "Error doing malloc for ringbuffer: %s\n", strerror(errno));
		exit(1);
	}
	memset(ringbuffer, 0, sizeof(struct Tringbuffer));
#endif

	if (!(_statistics = shared_malloc(sizeof(struct Tstats))))
	{
		LOG(0, 0, 0, "Error doing malloc for _statistics: %s\n", strerror(errno));
		exit(1);
	}
	if (!(tunnel = shared_malloc(sizeof(tunnelt) * MAXTUNNEL)))
	{
		LOG(0, 0, 0, "Error doing malloc for tunnels: %s\n", strerror(errno));
		exit(1);
	}
	if (!(bundle = shared_malloc(sizeof(bundlet) * MAXBUNDLE)))
	{
		LOG(0, 0, 0, "Error doing malloc for bundles: %s\n", strerror(errno));
		exit(1);
	}
	if (!(frag = shared_malloc(sizeof(fragmentationt) * MAXBUNDLE)))
	{
		LOG(0, 0, 0, "Error doing malloc for fragmentations: %s\n", strerror(errno));
		exit(1);
	}
	if (!(session = shared_malloc(sizeof(sessiont) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for sessions: %s\n", strerror(errno));
		exit(1);
	}

	if (!(sess_local = shared_malloc(sizeof(sessionlocalt) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for sess_local: %s\n", strerror(errno));
		exit(1);
	}

	if (!(radius = shared_malloc(sizeof(radiust) * MAXRADIUS)))
	{
		LOG(0, 0, 0, "Error doing malloc for radius: %s\n", strerror(errno));
		exit(1);
	}

	/* WTF?  Reassigning the address of an array? Must be left over from the older
		version before it was an array - removed by EKL
	if (!(ip_address_pool = shared_malloc(sizeof(ippoolt) * MAXIPPOOL)))
	{
		LOG(0, 0, 0, "Error doing malloc for ip_address_pool: %s\n", strerror(errno));
		exit(1);
	}
	*/

	if (!(ip_filters = shared_malloc(sizeof(ip_filtert) * MAXFILTER)))
	{
		LOG(0, 0, 0, "Error doing malloc for ip_filters: %s\n", strerror(errno));
		exit(1);
	}
	memset(ip_filters, 0, sizeof(ip_filtert) * MAXFILTER);

	if (!(cli_session_actions = shared_malloc(sizeof(struct cli_session_actions) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for cli session actions: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_session_actions, 0, sizeof(struct cli_session_actions) * MAXSESSION);

	if (!(cli_tunnel_actions = shared_malloc(sizeof(struct cli_tunnel_actions) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for cli tunnel actions: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_tunnel_actions, 0, sizeof(struct cli_tunnel_actions) * MAXSESSION);

	memset(tunnel, 0, sizeof(tunnelt) * MAXTUNNEL);
	memset(bundle, 0, sizeof(bundlet) * MAXBUNDLE);
	memset(session, 0, sizeof(sessiont) * MAXSESSION);
	memset(radius, 0, sizeof(radiust) * MAXRADIUS);
	//memset(ip_address_pool, 0, sizeof(ippoolt) * MAXIPPOOL); // see above - EKL

		// Put all the sessions on the free list marked as undefined.
	for (i = 1; i < MAXSESSION; i++)
	{
		session[i].next = i + 1;
		session[i].tunnel = T_UNDEF;	// mark it as not filled in.
	}
	session[MAXSESSION - 1].next = 0;
	sessionfree = 1;

		// Mark all the tunnels as undefined (waiting to be filled in by a download).
	for (i = 1; i < MAXTUNNEL; i++)
		tunnel[i].state = TUNNELUNDEF;	// mark it as not filled in.

	for (i = 1; i < MAXBUNDLE; i++) {
		bundle[i].state = BUNDLEUNDEF;
	}

	if (!*hostname)
	{
		// Grab my hostname unless it's been specified
		gethostname(hostname, sizeof(hostname));
		stripdomain(hostname);
	}

	_statistics->start_time = _statistics->last_reset = time(NULL);

#ifdef BGP
	if (!(bgp_peers = shared_malloc(sizeof(struct bgp_peer) * BGP_NUM_PEERS)))
	{
		LOG(0, 0, 0, "Error doing malloc for bgp: %s\n", strerror(errno));
		exit(1);
	}
#endif /* BGP */

	lac_initremotelnsdata();
}

static int assign_ip_address(sessionidt s)
{
	uint32_t i;
	int best = -1;
	time_t best_time = time_now;
	char *u = session[s].user;
	char reuse = 0;

        uint16_t x = (uint16_t)session[s].pool_id;

        // Get our pool and pool size for the approprate session.  Because sessions are 0 filled
        // this will default to [0]

        ippoolt *pool = ip_address_pool[x];
        int pool_size = ip_pool_size[x];

	CSTAT(assign_ip_address);

	/*
	 * By adding them to the default pool, we need to test at lines 3967 to make sure
	 * that we're not going to deref a null pointer.
	 * If the lines have changed, search for "uint8_t Uninitialized ip pool".
	 * Fixed 2009-06-22 by Rob
	 */
	if (pool == NULL)
	{
                LOG(0, s, session[s].tunnel, "assign_ip_address(): Uninitialized ip pool %d defaulting to default pool\n", session[s].pool_id);
                pool = ip_address_pool[0];
                pool_size = ip_pool_size[0];
	}

	for (i = 1; i < pool_size; i++)
	{
		if (!pool[i].address || pool[i].assigned)
			continue;

		if (!session[s].walled_garden && pool[i].user[0] && !strcmp(u, pool[i].user))
		{
			best = i;
			reuse = 1;
			break;
		}

		if (pool[i].last < best_time)
		{
			best = i;
			if (!(best_time = pool[i].last))
				break; // never used, grab this one
		}
	}

	if (best < 0)
	{
		LOG(0, s, session[s].tunnel, "assign_ip_address(): out of addresses\n");
		return 0;
	}

	session[s].ip = pool[best].address;
	session[s].ip_pool_index = best;
	pool[best].assigned = 1;
	pool[best].last = time_now;
	pool[best].session = s;
	if (session[s].walled_garden)
		/* Don't track addresses of users in walled garden (note: this
		   means that their address isn't "sticky" even if they get
		   un-gardened). */
		pool[best].user[0] = 0;
	else
		strncpy(pool[best].user, u, sizeof(pool[best].user) - 1);

	STAT(ip_allocated);
	LOG(4, s, session[s].tunnel, "assign_ip_address(): %s ip address %d from pool %d\n",
		reuse ? "Reusing" : "Allocating", best, session[s].pool_id);

	return 1;
}

static void free_ip_address(sessionidt s)
{
	int i = session[s].ip_pool_index;

        uint16_t x = (uint16_t)session[s].pool_id;

        ippoolt *pool = ip_address_pool[x];

	CSTAT(free_ip_address);

	if (!session[s].ip)
		return; // what the?

	if (i < 0)	// Is this actually part of the ip pool?
		i = 0;

	STAT(ip_freed);
	cache_ipmap(session[s].ip, -i);	// Change the mapping to point back to the ip pool index.
	session[s].ip = 0;

	/* 
	 * This causes a crash in the case of assigning to the default pool.
	 * If you change the behaviour here, you'll need to change it at line 3889
	 * If the lines have changed, search for "Uninitialized ip pool".
	 * Fixed 2009-06-22 by Rob
	 */	
	if (pool == NULL) {
		//Then we've added them to the default pool
		pool = ip_address_pool[0];
                LOG(0, s, session[s].tunnel, "free_ip_address(): Uninitialized ip pool %d removing ip used from default pool\n", session[s].pool_id);
	}
	pool[i].assigned = 0;
	pool[i].session = 0;
	pool[i].last = time_now;
}

//
// Fsck the address pool against the session table.
// Normally only called when we become a master.
//
// This isn't perfect: We aren't keep tracking of which
// users used to have an IP address.
//
void rebuild_address_pool(void)
{
        int x;
	int i;

        ippoolt *pool;

		//
		// Zero the IP pool allocation, and build
		// a map from IP address to pool index.
        for (x = 0; x<MAX_POOL_COUNT ; x++)
        {
                
                        if (ip_address_pool[x] == NULL)
                                continue;

                        for (i = 1; i < MAXIPPOOL; ++i)
                        {
                                ip_address_pool[x][i].assigned = 0;
                                ip_address_pool[x][i].session = 0;
                                if (!ip_address_pool[x][i].address)
                                        continue;
                                cache_ipmap(ip_address_pool[x][i].address, -i); // Map pool IP to pool index.
                        }
	}

	for (i = 0; i < MAXSESSION; ++i)
	{
		int ipid;
		if (!(session[i].opened && session[i].ip))
			continue;

		ipid = - lookup_ipmap(htonl(session[i].ip));

		if (session[i].ip_pool_index < 0)
		{
			// Not allocated out of the pool.
			if (ipid < 1)			// Not found in the pool either? good.
				continue;

			LOG(0, i, 0, "Session %u has an IP address (%s) that was marked static, but is in the pool (%d)!\n",
				i, fmtaddr(session[i].ip, 0), ipid);

			// Fall through and process it as part of the pool.
		}


		if (ipid > MAXIPPOOL || ipid < 0)
		{
			LOG(0, i, 0, "Session %u has a pool IP that's not found in the pool! (%d)\n", i, ipid);
			ipid = -1;
			session[i].ip_pool_index = ipid;
			continue;
		}

        pool = ip_address_pool[(uint)session[i].pool_id];

		pool[ipid].assigned = 1;
		pool[ipid].session = i;
		pool[ipid].last = time_now;
		strncpy(pool[ipid].user, session[i].user, sizeof(pool[ipid].user) - 1);
		session[i].ip_pool_index = ipid;
		cache_ipmap(session[i].ip, i);	// Fix the ip map.
	}
}

//
// Fix the address pool to match a changed session.
// (usually when the master sends us an update).
static void fix_address_pool(int sid)
{
        int ipid   = session[sid].ip_pool_index;

        uint16_t x  = (uint16_t)session[sid].pool_id;

	if (ipid > ip_pool_size[x])
		return;		// Ignore it. rebuild_address_pool will fix it up.

	if (ip_address_pool[x][ipid].address != session[sid].ip)
		return;		// Just ignore it. rebuild_address_pool will take care of it.

	ip_address_pool[x][ipid].assigned = 1;
	ip_address_pool[x][ipid].session = sid;
	ip_address_pool[x][ipid].last = time_now;
	strncpy(ip_address_pool[x][ipid].user, 
                session[sid].user, 
                sizeof(ip_address_pool[x][ipid].user) - 1);
}

//
// Add a block of addresses to the IP pool to hand out.
//
static void add_to_ip_pool(in_addr_t addr, in_addr_t mask,uint16_t x)
{
	int i;

        if (ip_address_pool[x] == NULL)
                malloc_pool(x);

	if (mask == 0)
		mask = 0xffffffff;	// Host route only.

	addr &= mask;

	if (ip_pool_size[x] >= MAXIPPOOL)	// Pool is full!
		return ;

	// +1 skips network address
	for (i = addr+1 ;(i & mask) == addr; ++i)
	{
		if (i == ((-1 & (~mask)) + addr))
			continue;	// Skip broadcast address.

		ip_address_pool[x][ip_pool_size[x]].address  = i;
		ip_address_pool[x][ip_pool_size[x]].assigned = 0;
		++ip_pool_size[x];
		if (ip_pool_size[x] >= MAXIPPOOL)
		{
			LOG(0, 0, 0, "Overflowed IP pool adding %s\n", fmtaddr(htonl(addr), 0));
			return;
		}
	}
}

void add_ip_range(char* buf, uint16_t x) {
	char *p;
	char *pool = buf;
	// Remove anything following the last newline.
	if ((p = (char *)strrchr(buf, '\n'))) *p = 0;
	if ((p = (char *)strchr(pool, '/')))
	{
		// It's a range
		int numbits = 0;
		in_addr_t start = 0, mask = 0;

		LOG(2, 0, 0, "Adding IP address range %s\n", buf);
		*p++ = 0;
		if (!*p || !(numbits = atoi(p)))
		{
			LOG(0, 0, 0, "Invalid pool range %s\n", buf);
			return;
		}
		start = ntohl(inet_addr(pool));
		mask = (in_addr_t) (pow(2, numbits) - 1) << (32 - numbits);

		// Add a static route for this pool
		LOG(5, 0, 0, "Adding route for address pool %s/%u\n",
			fmtaddr(htonl(start), 0), 32 + mask);

		routeset(0, start, mask, 0, 1);

		add_to_ip_pool(start, mask,x);
	}
	else
	{
		// It's a single ip address
	  add_to_ip_pool(ntohl(inet_addr(pool)), 0, x);
	}
}

// Initialize the IP address pool
void initippool(uint16_t x)
{
#define BUFSIZE 4096
	FILE *f;
	char *p;
	char buf[BUFSIZE];
        char filename[FILENAME_MAX];

        if (x) 
        {
        	snprintf(filename,sizeof(filename)-1,"%s-%d.dat",IPPOOLFILE,x);
        }
        else if (!x)
        {
        	strncpy(filename,IPPOOLFILE,sizeof(filename)-1);
        }
        
	if (!(f = fopen(filename, "r")))
	{
        	LOG(5, 0, 0, "Can't load pool file %s: %s\n", filename,strerror(errno));
        	return;
	}
	else {
		LOG(0, 0, 0, "Reading %s for pool %d\n", filename, x);
	}

        if (ip_address_pool[x] == NULL) 
        	malloc_pool(x);


	while (ip_pool_size[x] < MAXIPPOOL && fgets(buf, BUFSIZE, f))
	{
		char *pool = buf;
		buf[BUFSIZE-1] = 0;	// Force it to be zero terminated/

		if (*buf == '#' || *buf == '\n')
			continue; // Skip comments / blank lines

                // Remove anything following the last newline.
		if ((p = (char *)strrchr(buf, '\n'))) *p = 0;
		if ((p = (char *)strchr(buf, ':')))
		{
			in_addr_t src;
			*p = '\0';
			src = inet_addr(buf);
			if (src == INADDR_NONE)
			{
				LOG(0, 0, 0, "Invalid address pool IP %s\n", buf);
				exit(1);
			}
			// This entry is for a specific IP only
			if (src != config->bind_address)
				continue;
			*p = ':';
			pool = p+1;
		}
		if ((p = (char *)strchr(pool, '/')))
		{
			// It's a range
			int numbits = 0;
			in_addr_t start = 0, mask = 0;

			LOG(2, 0, 0, "Adding IP address range %s\n", buf);
			*p++ = 0;
			if (!*p || !(numbits = atoi(p)))
			{
				LOG(0, 0, 0, "Invalid pool range %s\n", buf);
				continue;
			}
			start = ntohl(inet_addr(pool));
			mask = (in_addr_t) (pow(2, numbits) - 1) << (32 - numbits);

			// Add a static route for this pool
			LOG(5, 0, 0, "Adding route for address pool %s/%u\n",
				fmtaddr(htonl(start), 0), 32 + mask);

			routeset(0, start, mask, 0, 1);

			add_to_ip_pool(start, mask,x);
		}
		else
		{
			// It's a single ip address
                  add_to_ip_pool(ntohl(inet_addr(pool)), 0, x);
		}
	}
	fclose(f);
	LOG(1, 0, 0, "IP address pool is %d addresses\n", (ip_pool_size[x] - 1));
}

void snoop_send_packet(uint8_t *packet, uint16_t size, in_addr_t destination, uint16_t port)
{
	struct sockaddr_in snoop_addr = {0};
	if (!destination || !port || snoopfd <= 0 || size <= 0 || !packet)
		return;

	snoop_addr.sin_family = AF_INET;
	snoop_addr.sin_addr.s_addr = destination;
	snoop_addr.sin_port = ntohs(port);

	LOG(5, 0, 0, "Snooping %d byte packet to %s:%u\n", size,
		fmtaddr(snoop_addr.sin_addr.s_addr, 0),
		htons(snoop_addr.sin_port));

	if (sendto(snoopfd, packet, size, MSG_DONTWAIT | MSG_NOSIGNAL, (void *) &snoop_addr, sizeof(snoop_addr)) < 0)
		LOG(0, 0, 0, "Error sending intercept packet: %s\n", strerror(errno));

	STAT(packets_snooped);
}

static int dump_session(FILE **f, sessiont *s)
{
	if (!s->opened || (!s->ip && !s->forwardtosession) || !(s->cin_delta || s->cout_delta) || !*s->user || s->walled_garden)
		return 1;

	if (!*f)
	{
		char filename[1024];
		char timestr[64];
		time_t now = time(NULL);

		strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S", localtime(&now));
		snprintf(filename, sizeof(filename), "%s/%s", config->accounting_dir, timestr);

		if (!(*f = fopen(filename, "w")))
		{
			LOG(0, 0, 0, "Can't write accounting info to %s: %s\n", filename, strerror(errno));
			return 0;
		}

		LOG(3, 0, 0, "Dumping accounting information to %s\n", filename);
		if(config->account_all_origin)
		{
		fprintf(*f, "# dslwatch.pl dump file V1.01\n"
			"# host: %s\n"
			"# endpoint: %s\n"
			"# time: %ld\n"
			"# uptime: %ld\n"
			"# format: username ip qos uptxoctets downrxoctets origin(L=LAC, R=Remote LNS, P=PPPOE)\n",
			hostname,
			fmtaddr(config->iftun_n_address[tunnel[s->tunnel].indexudp] ? config->iftun_n_address[tunnel[s->tunnel].indexudp] : my_address, 0),
			now,
			now - basetime);
		}
		else
		{
		fprintf(*f, "# dslwatch.pl dump file V1.01\n"
			"# host: %s\n"
			"# endpoint: %s\n"
			"# time: %ld\n"
			"# uptime: %ld\n"
			"# format: username ip qos uptxoctets downrxoctets\n",
			hostname,
			fmtaddr(config->iftun_n_address[tunnel[s->tunnel].indexudp] ? config->iftun_n_address[tunnel[s->tunnel].indexudp] : my_address, 0),
			now,
			now - basetime);
		}
	}

	LOG(4, 0, 0, "Dumping accounting information for %s\n", s->user);
	if(config->account_all_origin)
	{
	fprintf(*f, "%s %s %d %u %u %s\n",
		s->user,						// username
		fmtaddr(htonl(s->ip), 0),				// ip
		(s->throttle_in || s->throttle_out) ? 2 : 1,		// qos
		(uint32_t) s->cin_delta,				// uptxoctets
		(uint32_t) s->cout_delta,				// downrxoctets
		(s->tunnel == TUNNEL_ID_PPPOE)?"P":(tunnel[s->tunnel].isremotelns?"R":"L"));	// Origin
	}
	else if (!tunnel[s->tunnel].isremotelns && (s->tunnel != TUNNEL_ID_PPPOE))
	{
	fprintf(*f, "%s %s %d %u %u\n",
		s->user,						// username
		fmtaddr(htonl(s->ip), 0),				// ip
		(s->throttle_in || s->throttle_out) ? 2 : 1,		// qos
		(uint32_t) s->cin_delta,				// uptxoctets
		(uint32_t) s->cout_delta);				// downrxoctets
	}

	s->cin_delta = s->cout_delta = 0;

	return 1;
}

static void dump_acct_info(int all)
{
	int i;
	FILE *f = NULL;


	CSTAT(dump_acct_info);

	if (shut_acct_n)
	{
		for (i = 0; i < shut_acct_n; i++)
			dump_session(&f, &shut_acct[i]);

		shut_acct_n = 0;
	}

	if (all)
		for (i = 1; i <= config->cluster_highest_sessionid; i++)
			dump_session(&f, &session[i]);

	if (f)
		fclose(f);
}

// Main program
int main(int argc, char *argv[])
{
	int i;
	int optdebug = 0;
	char *optconfig = CONFIGFILE;
	int x;

	time(&basetime);             // start clock

	// scan args
	while ((i = getopt(argc, argv, "dvc:h:")) >= 0)
	{
		switch (i)
		{
		case 'd':
			if (fork()) exit(0);
			setsid();
			if(!freopen("/dev/null", "r", stdin)) LOG(0, 0, 0, "Error freopen stdin: %s\n", strerror(errno));
			if(!freopen("/dev/null", "w", stdout)) LOG(0, 0, 0, "Error freopen stdout: %s\n", strerror(errno));
			if(!freopen("/dev/null", "w", stderr)) LOG(0, 0, 0, "Error freopen stderr: %s\n", strerror(errno));
			break;
		case 'v':
			optdebug++;
			break;
		case 'c':
			optconfig = optarg;
			break;
		case 'h':
			snprintf(hostname, sizeof(hostname), "%s", optarg);
			break;
		default:
			printf("Args are:\n"
			       "\t-d\t\tDetach from terminal\n"
			       "\t-c <file>\tConfig file\n"
			       "\t-h <hostname>\tForce hostname\n"
			       "\t-v\t\tDebug\n");

			return (0);
			break;
		}
	}

	// Start the timer routine off
	time(&time_now);
	strftime(time_now_string, sizeof(time_now_string), "%Y-%m-%d %H:%M:%S", localtime(&time_now));

	initplugins();
	initdata(optdebug, optconfig);

	init_cli(hostname);
	read_config_file();
	/* set hostname /after/ having read the config file */
	if (*config->hostname)
		strcpy(hostname, config->hostname);
	cli_init_complete(hostname);
	update_config();
	init_tbf(config->num_tbfs);

	LOG(0, 0, 0, "L2TPNS version " VERSION "\n");
	LOG(0, 0, 0, "Copyright (c) 2012, 2013, 2014 ISP FDN & SAMESWIRELESS\n");
	LOG(0, 0, 0, "Copyright (c) 2003, 2004, 2005, 2006 Optus Internet Engineering\n");
	LOG(0, 0, 0, "Copyright (c) 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd) - GPL licenced\n");
	{
		struct rlimit rlim;
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;
		// Remove the maximum core size
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			LOG(0, 0, 0, "Can't set ulimit: %s\n", strerror(errno));

		// Make core dumps go to /tmp
		if(chdir("/tmp")) LOG(0, 0, 0, "Error chdir /tmp: %s\n", strerror(errno));
	}

	if (config->scheduler_fifo)
	{
		int ret;
		struct sched_param params = {0};
		params.sched_priority = 1;

		if (get_nprocs() < 2)
		{
			LOG(0, 0, 0, "Not using FIFO scheduler, there is only 1 processor in the system.\n");
			config->scheduler_fifo = 0;
		}
		else
		{
			if ((ret = sched_setscheduler(0, SCHED_FIFO, &params)) == 0)
			{
				LOG(1, 0, 0, "Using FIFO scheduler.  Say goodbye to any other processes running\n");
			}
			else
			{
				LOG(0, 0, 0, "Error setting scheduler to FIFO: %s\n", strerror(errno));
				config->scheduler_fifo = 0;
			}
		}
	}

	initnetlink();

	/* Set up the cluster communications port. */
	if (cluster_init() < 0)
		exit(1);

	inittun();
	LOG(1, 0, 0, "Set up on interface %s\n", config->tundevicename);

	if (*config->pppoe_if_to_bind)
	{
		init_pppoe();
		LOG(1, 0, 0, "Set up on pppoe interface %s\n", config->pppoe_if_to_bind);
	}

        for (x = 0; x<256;x++) {
            initippool(x);
        }
	if (!config->nbmultiaddress)
	{
		config->bind_n_address[0] = config->bind_address;
		config->nbmultiaddress++;
	}
	config->nbudpfd = config->nbmultiaddress;
	for (i = 0; i < config->nbudpfd; i++)
		initudp(&udpfd[i], config->bind_n_address[i]);
	initlacudp();
	config->indexlacudpfd = config->nbudpfd;
	udpfd[config->indexlacudpfd] = udplacfd;
	config->nbudpfd++;

	initcontrol();
	initdae();

	// Intercept
	snoopfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	initrad();
	dhcpv6_init();

	// seed prng
	{
		unsigned seed = time_now ^ getpid();
		LOG(4, 0, 0, "Seeding the pseudo random generator: %u\n", seed);
		srand(seed);
	}

	signal(SIGHUP,  sighup_handler);
	signal(SIGCHLD, sigchild_handler);
	signal(SIGTERM, shutdown_handler);
	signal(SIGINT,  shutdown_handler);
	signal(SIGQUIT, shutdown_handler);

	// Prevent us from getting paged out
	if (config->lock_pages)
	{
		if (!mlockall(MCL_CURRENT))
			LOG(1, 0, 0, "Locking pages into memory\n");
		else
			LOG(0, 0, 0, "Can't lock pages: %s\n", strerror(errno));
	}

	// Drop privileges here
//	if (config->target_uid > 0 && geteuid() == 0 && setuid(config->target_uid) != 0 )
//		return 1;

	mainloop();

	/* remove plugins (so cleanup code gets run) */
	plugins_done();

	// Remove the PID file if we wrote it
	if (config->wrote_pid && *config->pid_file == '/')
		unlink(config->pid_file);

	/* kill CLI children */
	signal(SIGTERM, SIG_IGN);
	kill(0, SIGTERM);
	return 0;
}

static void sighup_handler(int sig)
{
	main_reload++;
}

static void shutdown_handler(int sig)
{
	main_quit = (sig == SIGQUIT) ? QUIT_SHUTDOWN : QUIT_FAILOVER;
}

static void sigchild_handler(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0)
	    ;
}

static void build_chap_response(uint8_t *challenge, uint8_t id, uint16_t challenge_length, uint8_t **challenge_response)
{
	MD5_CTX ctx;
	*challenge_response = NULL;

	if (!*config->l2tp_secret)
	{
		LOG(0, 0, 0, "LNS requested CHAP authentication, but no l2tp secret is defined\n");
		return;
	}

	LOG(4, 0, 0, "   Building challenge response for CHAP request\n");

	*challenge_response = calloc(17, 1);

	MD5_Init(&ctx);
	MD5_Update(&ctx, &id, 1);
	MD5_Update(&ctx, config->l2tp_secret, strlen(config->l2tp_secret));
	MD5_Update(&ctx, challenge, challenge_length);
	MD5_Final(*challenge_response, &ctx);

	return;
}

static int facility_value(char *name)
{
	int i;
	for (i = 0; facilitynames[i].c_name; i++)
	{
		if (strcmp(facilitynames[i].c_name, name) == 0)
			return facilitynames[i].c_val;
	}
	return 0;
}

static void update_config()
{
	int i;
	char *p;
	static int timeout = 0;
	static int interval = 0;

	// Update logging
	closelog();
	syslog_log = 0;
	if (log_stream)
	{
		if (log_stream != stderr)
			fclose(log_stream);

		log_stream = NULL;
	}

	if (*config->log_filename)
	{
		if (strstr(config->log_filename, "syslog:") == config->log_filename)
		{
			char *p = config->log_filename + 7;
			if (*p)
			{
				openlog("l2tpns", LOG_PID, facility_value(p));
				syslog_log = 1;
			}
		}
		else if (strchr(config->log_filename, '/') == config->log_filename)
		{
			if ((log_stream = fopen((char *)(config->log_filename), "a")))
			{
				fseek(log_stream, 0, SEEK_END);
				setbuf(log_stream, NULL);
			}
			else
			{
				log_stream = stderr;
				setbuf(log_stream, NULL);
			}
		}
	}
	else
	{
		log_stream = stderr;
		setbuf(log_stream, NULL);
	}

#define L2TP_HDRS		(20+8+6+4)	// L2TP data encaptulation: ip + udp + l2tp (data) + ppp (inc hdlc)
#define TCP_HDRS		(20+20)		// TCP encapsulation: ip + tcp

	if (config->l2tp_mtu <= 0)		config->l2tp_mtu = 1500; // ethernet default
	else if (config->l2tp_mtu < MINMTU)	config->l2tp_mtu = MINMTU;
	else if (config->l2tp_mtu > MAXMTU)	config->l2tp_mtu = MAXMTU;

	// reset MRU/MSS globals
	MRU = config->l2tp_mtu - L2TP_HDRS;
	if (MRU > PPPoE_MRU)
		MRU = PPPoE_MRU;

	MSS = MRU - TCP_HDRS;

	// Update radius
	config->numradiusservers = 0;
	for (i = 0; i < MAXRADSERVER; i++)
		if (config->radiusserver[i])
		{
			config->numradiusservers++;
			// Set radius port: if not set, take the port from the
			// first radius server.  For the first radius server,
			// take the #defined default value from l2tpns.h

			// test twice, In case someone works with
			// a secondary radius server without defining
			// a primary one, this will work even then.
			if (i > 0 && !config->radiusport[i])
				config->radiusport[i] = config->radiusport[i-1];
			if (!config->radiusport[i])
				config->radiusport[i] = RADPORT;
		}

	if (!config->numradiusservers)
		LOG(0, 0, 0, "No RADIUS servers defined!\n");

	// parse radius_authtypes_s
	config->radius_authtypes = config->radius_authprefer = 0;
	p = config->radius_authtypes_s;
	while (p && *p)
	{
		char *s = strpbrk(p, " \t,");
		int type = 0;

		if (s)
		{
			*s++ = 0;
			while (*s == ' ' || *s == '\t')
				s++;

			if (!*s)
				s = 0;
		}

		if (!strncasecmp("chap", p, strlen(p)))
			type = AUTHCHAP;
		else if (!strncasecmp("pap", p, strlen(p)))
			type = AUTHPAP;
		else
			LOG(0, 0, 0, "Invalid RADIUS authentication type \"%s\"\n", p);

		config->radius_authtypes |= type;
		if (!config->radius_authprefer)
			config->radius_authprefer = type;

		p = s;
	}

	if (!config->radius_authtypes)
	{
		LOG(0, 0, 0, "Defaulting to PAP authentication\n");
		config->radius_authtypes = config->radius_authprefer = AUTHPAP;
	}

	// normalise radius_authtypes_s
	if (config->radius_authprefer == AUTHPAP)
	{
		strcpy(config->radius_authtypes_s, "pap");
		if (config->radius_authtypes & AUTHCHAP)
			strcat(config->radius_authtypes_s, ", chap");
	}
	else
	{
		strcpy(config->radius_authtypes_s, "chap");
		if (config->radius_authtypes & AUTHPAP)
			strcat(config->radius_authtypes_s, ", pap");
	}

	if (!config->radius_dae_port)
		config->radius_dae_port = DAEPORT;

	if(!config->bind_portremotelns)
		config->bind_portremotelns = L2TPLACPORT;
	if(!config->bind_address_remotelns)
		config->bind_address_remotelns = INADDR_ANY;

	if (*config->bind_multi_address)
	{
		char *sip = config->bind_multi_address;
		char *n = sip;
		char *e = config->bind_multi_address + strlen(config->bind_multi_address);
		config->nbmultiaddress = 0;

		while (*sip && (sip < e))
		{
			in_addr_t ip = 0;
			uint8_t u = 0;

			while (n < e && (*n == ',' || *n == ' ')) n++;

			while (n < e && (isdigit(*n) || *n == '.'))
			{
				 if (*n == '.')
				 {
					 ip = (ip << 8) + u;
					 u = 0;
				 }
				 else
					u = u * 10 + *n - '0';
				 n++;
			}
			ip = (ip << 8) + u;
			n++;

			if (ip)
			{
				config->bind_n_address[config->nbmultiaddress] = htonl(ip);
				config->iftun_n_address[config->nbmultiaddress] = htonl(ip);
				config->nbmultiaddress++;
				LOG(1, 0, 0, "Bind address %s\n", fmtaddr(htonl(ip), 0));

				if (config->nbmultiaddress >= MAX_BINDADDR) break;
			}

			sip = n;
		}

		if (config->nbmultiaddress >= 1)
		{
			config->bind_address = config->bind_n_address[0];
			config->iftun_address = config->bind_address;
		}
	}

	if(!config->iftun_address)
	{
		config->iftun_address = config->bind_address;
		config->iftun_n_address[0] = config->iftun_address;
	}

	if (*config->multi_hostname)
	{
		char *shost = config->multi_hostname;
		char *n = shost;
		char *e = config->multi_hostname + strlen(config->multi_hostname);
		config->nbmultihostname = 0;

		while (*shost && (shost < e))
		{
			while ((n < e) && (*n == ' ' || *n == ',' || *n == '\t')) n++;

			i = 0;
			while (n < e && (*n != ',') && (*n != '\t'))
			{
				config->multi_n_hostname[config->nbmultihostname][i] = *n;
				n++;i++;
			}

			if (i > 0)
			{
				config->multi_n_hostname[config->nbmultihostname][i] = 0;
				LOG(1, 0, 0, "Bind Hostname %s\n", config->multi_n_hostname[config->nbmultihostname]);
				config->nbmultihostname++;
				if (config->nbmultihostname >= MAX_NBHOSTNAME) break;
			}

			shost = n;
		}

		if (config->nbmultihostname >= 1)
		{
			strcpy(hostname, config->multi_n_hostname[0]);
			strcpy(config->hostname, hostname);
		}
	}

	if (!*config->pppoe_ac_name)
		strncpy(config->pppoe_ac_name, DEFAULT_PPPOE_AC_NAME, sizeof(config->pppoe_ac_name) - 1);

	// re-initialise the random number source
	initrandom(config->random_device);

	// Update plugins
	for (i = 0; i < MAXPLUGINS; i++)
	{
		if (strcmp(config->plugins[i], config->old_plugins[i]) == 0)
			continue;

		if (*config->plugins[i])
		{
			// Plugin added
			add_plugin(config->plugins[i]);
		}
		else if (*config->old_plugins[i])
		{
			// Plugin removed
			remove_plugin(config->old_plugins[i]);
		}
	}

	// Guest change
        guest_accounts_num = 0;
        char *p2 = config->guest_user;
        while (p2 && *p2)
        {
                char *s = strpbrk(p2, " \t,");
                if (s)
                {
                        *s++ = 0;
                        while (*s == ' ' || *s == '\t')
                                s++;

                        if (!*s)
                                s = 0;
                }

                strcpy(guest_users[guest_accounts_num], p2);
                LOG(1, 0, 0, "Guest account[%d]: %s\n", guest_accounts_num, guest_users[guest_accounts_num]);
                guest_accounts_num++;
                p2 = s;
        }
        // Rebuild the guest_user array
        strcpy(config->guest_user, "");
        int ui = 0;
        for (ui=0; ui<guest_accounts_num; ui++)
        {
                strcat(config->guest_user, guest_users[ui]);
                if (ui<guest_accounts_num-1)
                {
                        strcat(config->guest_user, ",");
                }
        }


	memcpy(config->old_plugins, config->plugins, sizeof(config->plugins));
	if (!config->multi_read_count) config->multi_read_count = 10;
	if (!config->cluster_address) config->cluster_address = inet_addr(DEFAULT_MCAST_ADDR);
	if (!*config->cluster_interface)
		strncpy(config->cluster_interface, DEFAULT_MCAST_INTERFACE, sizeof(config->cluster_interface) - 1);

	if (!config->cluster_hb_interval)
		config->cluster_hb_interval = PING_INTERVAL;	// Heartbeat every 0.5 seconds.

	if (!config->cluster_hb_timeout)
		config->cluster_hb_timeout = HB_TIMEOUT;	// 10 missed heartbeat triggers an election.

	if (interval != config->cluster_hb_interval || timeout != config->cluster_hb_timeout)
	{
		// Paranoia:  cluster_check_master() treats 2 x interval + 1 sec as
		// late, ensure we're sufficiently larger than that
		int t = 4 * config->cluster_hb_interval + 11;

		if (config->cluster_hb_timeout < t)
		{
			LOG(0, 0, 0, "Heartbeat timeout %d too low, adjusting to %d\n", config->cluster_hb_timeout, t);
			config->cluster_hb_timeout = t;
		}

		// Push timing changes to the slaves immediately if we're the master
		if (config->cluster_iam_master)
			cluster_heartbeat();

		interval = config->cluster_hb_interval;
		timeout = config->cluster_hb_timeout;
	}

	// Write PID file
	if (*config->pid_file == '/' && !config->wrote_pid)
	{
		FILE *f;
		if ((f = fopen(config->pid_file, "w")))
		{
			fprintf(f, "%d\n", getpid());
			fclose(f);
			config->wrote_pid = 1;
		}
		else
		{
			LOG(0, 0, 0, "Can't write to PID file %s: %s\n", config->pid_file, strerror(errno));
		}
	}
}

static void read_config_file()
{
	FILE *f;

	if (!config->config_file) return;
	if (!(f = fopen(config->config_file, "r")))
	{
		fprintf(stderr, "Can't open config file %s: %s\n", config->config_file, strerror(errno));
		return;
	}

	LOG(3, 0, 0, "Reading config file %s\n", config->config_file);
	cli_do_file(f);
	LOG(3, 0, 0, "Done reading config file\n");
	fclose(f);
}

int sessionsetup(sessionidt s, tunnelidt t)
{
	// A session now exists, set it up
	in_addr_t ip;
	char *user;
	sessionidt i;
	int r;

	CSTAT(sessionsetup);

	LOG(3, s, t, "Doing session setup for session\n");

	// Join a bundle if the MRRU option is accepted
	if(session[s].mrru > 0 && session[s].bundle == 0)
	{
		LOG(3, s, t, "This session can be part of multilink bundle\n");
		if (join_bundle(s) > 0)
			cluster_send_bundle(session[s].bundle);
		else
		{
			LOG(0, s, t, "MPPP: Mismaching mssf option with other sessions in bundle\n");
			sessionshutdown(s, "Mismaching mssf option.", CDN_NONE, TERM_SERVICE_UNAVAILABLE);
			return 0;
		}
	}

	if (!session[s].ip)
	{
		assign_ip_address(s);
		if (!session[s].ip)
		{
			LOG(0, s, t, "   No IP allocated.  The IP address pool is FULL!\n");
			sessionshutdown(s, "No IP addresses available.", CDN_TRY_ANOTHER, TERM_SERVICE_UNAVAILABLE);
			return 0;
		}
		LOG(3, s, t, "   No IP allocated.  Assigned %s from pool\n",
			fmtaddr(htonl(session[s].ip), 0));
	}

	// Make sure this is right
	session[s].tunnel = t;

	// zap old sessions with same IP and/or username
	// Don't kill gardened sessions - doing so leads to a DoS
	// from someone who doesn't need to know the password
	{
		ip = session[s].ip;
		user = session[s].user;
		for (i = 1; i <= config->cluster_highest_sessionid; i++)
		{
			if (i == s) continue;
			if (!session[s].opened) break;
			// Allow duplicate sessions for multilink ones of the same bundle.
			if (session[s].bundle && session[i].bundle && session[s].bundle == session[i].bundle) continue;

			if (ip == session[i].ip)
			{
				sessionshutdown(i, "Duplicate IP address", CDN_ADMIN_DISC, TERM_ADMIN_RESET);  // close radius/routes, etc.
				continue;
			}

			if (config->allow_duplicate_users) continue;
			if (session[s].walled_garden || session[i].walled_garden) continue;
			// Guest change
			int found = 0;
			int gu;
			for (gu = 0; gu < guest_accounts_num; gu++)
			{
				if (!strcasecmp(user, guest_users[gu]))
				{
					found = 1;
					break;
				}
			}
			if (found) continue;

			// Drop the new session in case of duplicate sessionss, not the old one.
			if (!strcasecmp(user, session[i].user))
				sessionshutdown(i, "Duplicate session for users", CDN_ADMIN_DISC, TERM_ADMIN_RESET);  // close radius/routes, etc.
		}
	}

	// no need to set a route for the same IP address of the bundle
	if (!session[s].bundle || (bundle[session[s].bundle].num_of_links == 1))
	{
		int routed = 0;

		// Add the route for this session.
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			if ((session[s].ip >> (32-session[s].route[r].prefixlen)) ==
			    (session[s].route[r].ip >> (32-session[s].route[r].prefixlen)))
				routed++;

			routeset(s, session[s].route[r].ip, session[s].route[r].prefixlen, 0, 1);
		}

		// Static IPs need to be routed if not already
		// convered by a Framed-Route.  Anything else is part
		// of the IP address pool and is already routed, it
		// just needs to be added to the IP cache.
		// IPv6 route setup is done in ppp.c, when IPV6CP is acked.
		if (session[s].ip_pool_index == -1) // static ip
		{
			if (!routed) routeset(s, session[s].ip, 0, 0, 1);
		}
		else
			cache_ipmap(session[s].ip, s);
	}

	sess_local[s].lcp_authtype = 0; // RADIUS authentication complete
	lcp_open(s, t); // transition to Network phase and send initial IPCP

	// Run the plugin's against this new session.
	{
		struct param_new_session data = { &tunnel[t], &session[s] };
		run_plugins(PLUGIN_NEW_SESSION, &data);
	}

	#ifdef ISEEK_CONTROL_MESSAGE
	LOG(1, s, t, "iseek-control-message login %s %d/%d %s\n", session[s].user, session[s].tx_connect_speed, session[s].rx_connect_speed, fmtaddr(htonl(session[s].ip), 0));
	#endif

	// Allocate TBFs if throttled
	if (session[s].throttle_in || session[s].throttle_out)
		throttle_session(s, session[s].throttle_in, session[s].throttle_out);

	session[s].last_packet = session[s].last_data = time_now;

	LOG(2, s, t, "Login by %s at %s from %s (%s)\n", session[s].user,
		fmtaddr(htonl(session[s].ip), 0),
		fmtaddr(htonl(tunnel[t].ip), 1), tunnel[t].hostname);

	cluster_send_session(s);	// Mark it as dirty, and needing to the flooded to the cluster.

	return 1;       // RADIUS OK and IP allocated, done...
}

//
// This session just got dropped on us by the master or something.
// Make sure our tables up up to date...
//
int load_session(sessionidt s, sessiont *new)
{
	int i;
	int newip = 0;

		// Sanity checks.
	if (new->ip_pool_index >= MAXIPPOOL ||
		new->tunnel >= MAXTUNNEL)
	{
		LOG(0, s, 0, "Strange session update received!\n");
			// FIXME! What to do here?
		return 0;
	}

		//
		// Ok. All sanity checks passed. Now we're committed to
		// loading the new session.
		//

	session[s].tunnel = new->tunnel; // For logging in cache_ipmap

	// See if routes/ip cache need updating
	if (new->ip != session[s].ip)
		newip++;

	for (i = 0; !newip && i < MAXROUTE && (session[s].route[i].ip || new->route[i].ip); i++)
		if (new->route[i].ip != session[s].route[i].ip ||
		    new->route[i].prefixlen != session[s].route[i].prefixlen)
			newip++;

	// needs update
	if (newip)
	{
		int routed = 0;

		// remove old routes...
		for (i = 0; i < MAXROUTE && session[s].route[i].ip; i++)
		{
			if ((session[s].ip >> (32-session[s].route[i].prefixlen)) ==
			    (session[s].route[i].ip >> (32-session[s].route[i].prefixlen)))
				routed++;

			routeset(s, session[s].route[i].ip, session[s].route[i].prefixlen, 0, 0);
		}

		// ...ip
		if (session[s].ip)
		{
			if (session[s].ip_pool_index == -1) // static IP
			{
				if (!routed) routeset(s, session[s].ip, 0, 0, 0);
			}
			else		// It's part of the IP pool, remove it manually.
				uncache_ipmap(session[s].ip);
		}

		// remove old IPV6 routes...
		for (i = 0; i < MAXROUTE6 && session[s].route6[i].ipv6route.s6_addr[0] && session[s].route6[i].ipv6prefixlen; i++)
		{
			route6set(s, session[s].route6[i].ipv6route, session[s].route6[i].ipv6prefixlen, 0);
		}

		if (session[s].ipv6address.s6_addr[0])
		{
			route6set(s, session[s].ipv6address, 128, 0);
		}

		routed = 0;

		// add new routes...
		for (i = 0; i < MAXROUTE && new->route[i].ip; i++)
		{
			if ((new->ip >> (32-new->route[i].prefixlen)) ==
			    (new->route[i].ip >> (32-new->route[i].prefixlen)))
				routed++;

			routeset(s, new->route[i].ip, new->route[i].prefixlen, 0, 1);
		}

		// ...ip
		if (new->ip)
		{
			// If there's a new one, add it.
			if (new->ip_pool_index == -1)
			{
				if (!routed) routeset(s, new->ip, 0, 0, 1);
			}
			else
				cache_ipmap(new->ip, s);
		}
	}

	// check v6 routing
	if (new->ppp.ipv6cp == Opened && session[s].ppp.ipv6cp != Opened)
	{
		for (i = 0; i < MAXROUTE6 && new->route6[i].ipv6prefixlen; i++)
		{
			route6set(s, new->route6[i].ipv6route, new->route6[i].ipv6prefixlen, 1);
		}
	}

	if (new->ipv6address.s6_addr[0] && new->ppp.ipv6cp == Opened && session[s].ppp.ipv6cp != Opened)
	{
		// Check if included in prefix
		if (sessionbyipv6(new->ipv6address) != s)
			route6set(s, new->ipv6address, 128, 1);
	}

	// check filters
	if (new->filter_in && (new->filter_in > MAXFILTER || !ip_filters[new->filter_in - 1].name[0]))
	{
		LOG(2, s, session[s].tunnel, "Dropping invalid input filter %u\n", (int) new->filter_in);
		new->filter_in = 0;
	}

	if (new->filter_out && (new->filter_out > MAXFILTER || !ip_filters[new->filter_out - 1].name[0]))
	{
		LOG(2, s, session[s].tunnel, "Dropping invalid output filter %u\n", (int) new->filter_out);
		new->filter_out = 0;
	}

	if (new->filter_in != session[s].filter_in)
	{
		if (session[s].filter_in) ip_filters[session[s].filter_in - 1].used--;
		if (new->filter_in)       ip_filters[new->filter_in - 1].used++;
	}

	if (new->filter_out != session[s].filter_out)
	{
		if (session[s].filter_out) ip_filters[session[s].filter_out - 1].used--;
		if (new->filter_out)       ip_filters[new->filter_out - 1].used++;
	}

	if (new->tunnel && s > config->cluster_highest_sessionid)	// Maintain this in the slave. It's used
					// for walking the sessions to forward byte counts to the master.
		config->cluster_highest_sessionid = s;

	memcpy(&session[s], new, sizeof(session[s]));	// Copy over..

		// Do fixups into address pool.
	if (new->ip_pool_index != -1)
		fix_address_pool(s);

	return 1;
}

static void initplugins()
{
	int i;

	loaded_plugins = ll_init();
	// Initialize the plugins to nothing
	for (i = 0; i < MAX_PLUGIN_TYPES; i++)
		plugins[i] = ll_init();
}

static void *open_plugin(char *plugin_name, int load)
{
	char path[256] = "";

	snprintf(path, 256, PLUGINDIR "/%s.so", plugin_name);
	LOG(2, 0, 0, "%soading plugin from %s\n", load ? "L" : "Un-l", path);
	return dlopen(path, RTLD_NOW);
}

// plugin callback to get a config value
static void *getconfig(char *key, enum config_typet type)
{
	int i;

	for (i = 0; config_values[i].key; i++)
	{
		if (!strcmp(config_values[i].key, key))
		{
			if (config_values[i].type == type)
				return ((void *) config) + config_values[i].offset;

			LOG(1, 0, 0, "plugin requested config item \"%s\" expecting type %d, have type %d\n",
				key, type, config_values[i].type);

			return 0;
		}
	}

	LOG(1, 0, 0, "plugin requested unknown config item \"%s\"\n", key);
	return 0;
}

static int add_plugin(char *plugin_name)
{
	static struct pluginfuncs funcs = {
		_log,
		_log_hex,
		fmtaddr,
		sessionbyuser,
		sessiontbysessionidt,
		sessionidtbysessiont,
		radiusnew,
		radiussend,
		getconfig,
		sessionshutdown,
		sessionkill,
		throttle_session,
		cluster_send_session,
	};

	void *p = open_plugin(plugin_name, 1);
	int (*initfunc)(struct pluginfuncs *);
	int i;

	if (!p)
	{
		LOG(1, 0, 0, "   Plugin load failed: %s\n", dlerror());
		return -1;
	}

	if (ll_contains(loaded_plugins, p))
	{
		dlclose(p);
		return 0; // already loaded
	}

	{
		int *v = dlsym(p, "plugin_api_version");
		if (!v || *v != PLUGIN_API_VERSION)
		{
			LOG(1, 0, 0, "   Plugin load failed: API version mismatch: %s\n", dlerror());
			dlclose(p);
			return -1;
		}
	}

	if ((initfunc = dlsym(p, "plugin_init")))
	{
		if (!initfunc(&funcs))
		{
			LOG(1, 0, 0, "   Plugin load failed: plugin_init() returned FALSE: %s\n", dlerror());
			dlclose(p);
			return -1;
		}
	}

	ll_push(loaded_plugins, p);

	for (i = 0; i < max_plugin_functions; i++)
	{
		void *x;
		if (plugin_functions[i] && (x = dlsym(p, plugin_functions[i])))
		{
			LOG(3, 0, 0, "   Supports function \"%s\"\n", plugin_functions[i]);
			ll_push(plugins[i], x);
		}
	}

	LOG(2, 0, 0, "   Loaded plugin %s\n", plugin_name);
	return 1;
}

static void run_plugin_done(void *plugin)
{
	int (*donefunc)(void) = dlsym(plugin, "plugin_done");

	if (donefunc)
		donefunc();
}

static int remove_plugin(char *plugin_name)
{
	void *p = open_plugin(plugin_name, 0);
	int loaded = 0;

	if (!p)
		return -1;

	if (ll_contains(loaded_plugins, p))
	{
		int i;
		for (i = 0; i < max_plugin_functions; i++)
		{
			void *x;
			if (plugin_functions[i] && (x = dlsym(p, plugin_functions[i])))
				ll_delete(plugins[i], x);
		}

		ll_delete(loaded_plugins, p);
		run_plugin_done(p);
		loaded = 1;
	}

	dlclose(p);
	LOG(2, 0, 0, "Removed plugin %s\n", plugin_name);
	return loaded;
}

int run_plugins(int plugin_type, void *data)
{
	int (*func)(void *data);

	if (!plugins[plugin_type] || plugin_type > max_plugin_functions)
		return PLUGIN_RET_ERROR;

	ll_reset(plugins[plugin_type]);
	while ((func = ll_next(plugins[plugin_type])))
	{
		int r = func(data);

		if (r != PLUGIN_RET_OK)
			return r; // stop here
	}

	return PLUGIN_RET_OK;
}

static void plugins_done()
{
	void *p;

	ll_reset(loaded_plugins);
	while ((p = ll_next(loaded_plugins)))
		run_plugin_done(p);
}

static void processcontrol(uint8_t *buf, int len, struct sockaddr_in *addr, int alen, struct in_addr *local)
{
	struct nsctl request;
	struct nsctl response;
	int type = unpack_control(&request, buf, len);
	int r;
	void *p;

	if (log_stream && config->debug >= 4)
	{
		if (type < 0)
		{
			LOG(4, 0, 0, "Bogus control message from %s (%d)\n",
				fmtaddr(addr->sin_addr.s_addr, 0), type);
		}
		else
		{
			LOG(4, 0, 0, "Received [%s] ", fmtaddr(addr->sin_addr.s_addr, 0));
			dump_control(&request, log_stream);
		}
	}

	switch (type)
	{
	case NSCTL_REQ_LOAD:
		if (request.argc != 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = "name of plugin required";
		}
		else if ((r = add_plugin(request.argv[0])) < 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = !r
				? "plugin already loaded"
				: "error loading plugin";
		}
		else
		{
			response.type = NSCTL_RES_OK;
			response.argc = 0;
		}

		break;

	case NSCTL_REQ_UNLOAD:
		if (request.argc != 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = "name of plugin required";
		}
		else if ((r = remove_plugin(request.argv[0])) < 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = !r
				? "plugin not loaded"
				: "plugin not found";
		}
		else
		{
			response.type = NSCTL_RES_OK;
			response.argc = 0;
		}

		break;

	case NSCTL_REQ_HELP:
		response.type = NSCTL_RES_OK;
		response.argc = 0;

		ll_reset(loaded_plugins);
		while ((p = ll_next(loaded_plugins)))
		{
			char **help = dlsym(p, "plugin_control_help");
			while (response.argc < 0xff && help && *help)
				response.argv[response.argc++] = *help++;
		}

		break;

	case NSCTL_REQ_CONTROL:
		{
			struct param_control param = {
				config->cluster_iam_master,
				request.argc,
				request.argv,
				0,
				NULL,
			};

			int r = run_plugins(PLUGIN_CONTROL, &param);

			if (r == PLUGIN_RET_ERROR)
			{
				response.type = NSCTL_RES_ERR;
				response.argc = 1;
				response.argv[0] = param.additional
					? param.additional
					: "error returned by plugin";
			}
			else if (r == PLUGIN_RET_NOTMASTER)
			{
				static char msg[] = "must be run on master: 000.000.000.000";

				response.type = NSCTL_RES_ERR;
				response.argc = 1;
				if (config->cluster_master_address)
				{
					strcpy(msg + 23, fmtaddr(config->cluster_master_address, 0));
					response.argv[0] = msg;
				}
				else
				{
				    	response.argv[0] = "must be run on master: none elected";
				}
			}
			else if (!(param.response & NSCTL_RESPONSE))
			{
				response.type = NSCTL_RES_ERR;
				response.argc = 1;
				response.argv[0] = param.response
					? "unrecognised response value from plugin"
					: "unhandled action";
			}
			else
			{
				response.type = param.response;
				response.argc = 0;
				if (param.additional)
				{
					response.argc = 1;
					response.argv[0] = param.additional;
				}
			}
		}

		break;

	default:
		response.type = NSCTL_RES_ERR;
		response.argc = 1;
		response.argv[0] = "error unpacking control packet";
	}

	buf = calloc(NSCTL_MAX_PKT_SZ, 1);
	if (!buf)
	{
		LOG(2, 0, 0, "Failed to allocate nsctl response\n");
		return;
	}

	r = pack_control(buf, NSCTL_MAX_PKT_SZ, response.type, response.argc, response.argv);
	if (r > 0)
	{
		sendtofrom(controlfd, buf, r, 0, (const struct sockaddr *) addr, alen, local);
		if (log_stream && config->debug >= 4)
		{
			LOG(4, 0, 0, "Sent [%s] ", fmtaddr(addr->sin_addr.s_addr, 0));
			dump_control(&response, log_stream);
		}
	}
	else
		LOG(2, 0, 0, "Failed to pack nsctl response for %s (%d)\n",
			fmtaddr(addr->sin_addr.s_addr, 0), r);

	free(buf);
}

static tunnelidt new_tunnel()
{
	tunnelidt i;
	for (i = 1; i < MAXTUNNEL; i++)
	{
		if ((tunnel[i].state == TUNNELFREE) && (i != TUNNEL_ID_PPPOE))
		{
			LOG(4, 0, i, "Assigning tunnel ID %u\n", i);
			if (i > config->cluster_highest_tunnelid)
				config->cluster_highest_tunnelid = i;
			return i;
		}
	}
	LOG(0, 0, 0, "Can't find a free tunnel! There shouldn't be this many in use!\n");
	return 0;
}

//
// We're becoming the master. Do any required setup..
//
// This is principally telling all the plugins that we're
// now a master, and telling them about all the sessions
// that are active too..
//
void become_master(void)
{
	int s, i;
	static struct event_data d[RADIUS_FDS];
	struct epoll_event e;

	run_plugins(PLUGIN_BECOME_MASTER, NULL);

	// running a bunch of iptables commands is slow and can cause
	// the master to drop tunnels on takeover--kludge around the
	// problem by forking for the moment (note: race)
	if (!fork_and_close())
	{
		for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
		{
			if (!session[s].opened) // Not an in-use session.
				continue;

			run_plugins(PLUGIN_NEW_SESSION_MASTER, &session[s]);
		}
		exit(0);
	}

	// add radius fds
	e.events = EPOLLIN;
	for (i = 0; i < RADIUS_FDS; i++)
	{
	    	d[i].type = FD_TYPE_RADIUS;
		d[i].index = i;
		e.data.ptr = &d[i];

		epoll_ctl(epollfd, EPOLL_CTL_ADD, radfds[i], &e);
	}
}

int cmd_show_hist_idle(struct cli_def *cli, const char *command, char **argv, int argc)
{
	int s, i;
	int count = 0;
	int buckets[64];

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	time(&time_now);
	for (i = 0; i < 64;++i) buckets[i] = 0;

	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
	{
		int idle;
		if (!session[s].opened)
			continue;

		idle = time_now - session[s].last_data;
		idle /= 5 ; // In multiples of 5 seconds.
		if (idle < 0)
			idle = 0;
		if (idle > 63)
			idle = 63;

		++count;
		++buckets[idle];
	}

	for (i = 0; i < 63; ++i)
	{
		if (count == 0)
			cli_print (cli,"  %3d seconds  : %7.2f%% (%6d)", i*5, (double) 0.0, buckets[i]);
		else 
			cli_print(cli, "  %3d seconds  : %7.2f%% (%6d)", i * 5, (double) buckets[i] * 100.0 / count , buckets[i]);
	}
	if (count == 0)
		cli_print(cli, "\tlots of secs : %7.2f%% (%6d)", (double) 0.0 , buckets[i]);
	else cli_print(cli, "\tlots of secs : %7.2f%% (%6d)", (double) buckets[63] * 100.0 / count , buckets[i]);
	cli_print(cli, "\t%d total sessions open.", count);
	return CLI_OK;
}

int cmd_show_hist_open(struct cli_def *cli, const char *command, char **argv, int argc)
{
	int s, i;
	int count = 0;
	int buckets[64];

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	time(&time_now);
	for (i = 0; i < 64;++i) buckets[i] = 0;

	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
	{
		int open = 0, d;
		if (!session[s].opened)
			continue;

		d = time_now - session[s].opened;
		if (d < 0)
			d = 0;
		while (d > 1 && open < 32)
		{
			++open;
			d >>= 1; // half.
		}
		++count;
		++buckets[open];
	}

	s = 1;
	for (i = 0; i  < 30; ++i)
	{
		if (count == 0)
			cli_print(cli, " < %12d seconds : %7.2f%% (%6d)", s, (double)0.0, buckets[i]);
		else cli_print(cli, " < %12d seconds : %7.2f%% (%6d)", s, (double) buckets[i] * 100.0 / count , buckets[i]);
		s <<= 1;
	}
	cli_print(cli, "\t%d total sessions open.", count);
	return CLI_OK;
}

/* Unhide an avp.
 *
 * This unencodes the AVP using the L2TP secret and the previously
 * stored random vector.  It overwrites the hidden data with the
 * unhidden AVP subformat.
 */
static void unhide_value(uint8_t *value, size_t len, uint16_t type, uint8_t *vector, size_t vec_len)
{
	MD5_CTX ctx;
	uint8_t digest[16];
	uint8_t *last;
	size_t d = 0;
	uint16_t m = htons(type);

	// Compute initial pad
	MD5_Init(&ctx);
	MD5_Update(&ctx, (unsigned char *) &m, 2);
	MD5_Update(&ctx, config->l2tp_secret, strlen(config->l2tp_secret));
	MD5_Update(&ctx, vector, vec_len);
	MD5_Final(digest, &ctx);

	// pointer to last decoded 16 octets
	last = value;

	while (len > 0)
	{
		// calculate a new pad based on the last decoded block
		if (d >= sizeof(digest))
		{
			MD5_Init(&ctx);
			MD5_Update(&ctx, config->l2tp_secret, strlen(config->l2tp_secret));
			MD5_Update(&ctx, last, sizeof(digest));
			MD5_Final(digest, &ctx);

			d = 0;
			last = value;
		}

		*value++ ^= digest[d++];
		len--;
	}
}

int find_filter(char const *name, size_t len)
{
	int free = -1;
	int i;

	for (i = 0; i < MAXFILTER; i++)
	{
	    	if (!*ip_filters[i].name)
		{
			if (free < 0)
				free = i;

			continue;
		}

		if (strlen(ip_filters[i].name) != len)
			continue;

		if (!strncmp(ip_filters[i].name, name, len))
			return i;
	}
			
	return free;
}

static int ip_filter_port(ip_filter_portt *p, uint16_t port)
{
	switch (p->op)
	{
	case FILTER_PORT_OP_EQ:    return port == p->port;
	case FILTER_PORT_OP_NEQ:   return port != p->port;
	case FILTER_PORT_OP_GT:    return port > p->port;
	case FILTER_PORT_OP_LT:    return port < p->port;
	case FILTER_PORT_OP_RANGE: return port >= p->port && port <= p->port2;
	}

	return 0;
}

static int ip_filter_flag(uint8_t op, uint8_t sflags, uint8_t cflags, uint8_t flags)
{
	switch (op)
	{
	case FILTER_FLAG_OP_ANY:
		return (flags & sflags) || (~flags & cflags);

	case FILTER_FLAG_OP_ALL:
		return (flags & sflags) == sflags && (~flags & cflags) == cflags;

	case FILTER_FLAG_OP_EST:
		return (flags & (TCP_FLAG_ACK|TCP_FLAG_RST)) && (~flags & TCP_FLAG_SYN);
	}

	return 0;
}

int ip_filter(uint8_t *buf, int len, uint8_t filter)
{
	uint16_t frag_offset;
	uint8_t proto;
    	in_addr_t src_ip;
	in_addr_t dst_ip;
	uint16_t src_port = 0;
	uint16_t dst_port = 0;
	uint8_t flags = 0;
	ip_filter_rulet *rule;

    	if (len < 20) // up to end of destination address
		return 0;

	if ((*buf >> 4) != 4) // IPv4
		return 0;

	frag_offset = ntohs(*(uint16_t *) (buf + 6)) & 0x1fff;
	proto = buf[9];
	src_ip = *(in_addr_t *) (buf + 12);
	dst_ip = *(in_addr_t *) (buf + 16);

	if (frag_offset == 0 && (proto == IPPROTO_TCP || proto == IPPROTO_UDP))
	{
		int l = (buf[0] & 0xf) * 4; // length of IP header
		if (len < l + 4) // ports
			return 0;

		src_port = ntohs(*(uint16_t *) (buf + l));
		dst_port = ntohs(*(uint16_t *) (buf + l + 2));
		if (proto == IPPROTO_TCP)
		{
		    	if (len < l + 14) // flags
				return 0;

			flags = buf[l + 13] & 0x3f;
		}
	}

	for (rule = ip_filters[filter].rules; rule->action; rule++)
	{
		if (rule->proto != IPPROTO_IP && proto != rule->proto)
			continue;

		if (rule->src_wild != INADDR_BROADCAST &&
		    (src_ip & ~rule->src_wild) != (rule->src_ip & ~rule->src_wild))
			continue;

		if (rule->dst_wild != INADDR_BROADCAST &&
		    (dst_ip & ~rule->dst_wild) != (rule->dst_ip & ~rule->dst_wild))
			continue;

		if (frag_offset)
		{
			// layer 4 deny rules are skipped
			if (rule->action == FILTER_ACTION_DENY &&
			    (rule->src_ports.op || rule->dst_ports.op || rule->tcp_flag_op))
				continue;
		}
		else
		{
			if (rule->frag)
				continue;

			if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
			{
				if (rule->src_ports.op && !ip_filter_port(&rule->src_ports, src_port))
					continue;

				if (rule->dst_ports.op && !ip_filter_port(&rule->dst_ports, dst_port))
					continue;

				if (proto == IPPROTO_TCP && rule->tcp_flag_op &&
				    !ip_filter_flag(rule->tcp_flag_op, rule->tcp_sflags, rule->tcp_cflags, flags))
					continue;
			}
		}

		// matched
		rule->counter++;
		return rule->action == FILTER_ACTION_PERMIT;
	}

	// default deny
    	return 0;
}

tunnelidt lac_new_tunnel()
{
	return new_tunnel();
}

void lac_tunnelclear(tunnelidt t)
{
	tunnelclear(t);
}

void lac_send_SCCRQ(tunnelidt t, uint8_t * auth, unsigned int auth_len)
{
	uint16_t version = 0x0100;	// protocol version

	tunnel[t].state = TUNNELOPENING;

	// Sent SCCRQ - Start Control Connection Request
	controlt *c = controlnew(1); // sending SCCRQ
	controls(c, 7, config->multi_n_hostname[tunnel[t].indexudp][0]?config->multi_n_hostname[tunnel[t].indexudp]:hostname, 1); // host name
	controls(c, 8, Vendor_name, 1); // Vendor name
	control16(c, 2, version, 1); // protocol version
	control32(c, 3, 3, 1); // framing Capabilities
	control16(c, 9, t, 1); // assigned tunnel
	controlb(c, 11, (uint8_t *) auth, auth_len, 1);  // CHAP Challenge
	LOG(3, 0, t, "Sent SCCRQ to REMOTE LNS\n");
	controladd(c, 0, t); // send
}

void lac_send_ICRQ(tunnelidt t, sessionidt s)
{
	// Sent ICRQ  Incoming-call-request
	controlt *c = controlnew(10); // ICRQ

	control16(c, 14, s, 1); // assigned sesion
	call_serial_number++;
	control32(c, 15, call_serial_number, 1);  // call serial number
	LOG(3, s, t, "Sent ICRQ to REMOTE LNS (far ID %u)\n", tunnel[t].far);
	controladd(c, 0, t); // send
}

void lac_tunnelshutdown(tunnelidt t, char *reason, int result, int error, char *msg)
{
	tunnelshutdown(t, reason, result, error, msg);
}

