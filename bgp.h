/* BGPv4 (RFC1771) */
/* $Id: bgp.h,v 1.5 2005-06-04 15:42:35 bodea Exp $ */

#ifndef __BGP_H__
#define __BGP_H__

#define BGP_MAX_PACKET_SIZE	4096
#define BGP_HOLD_TIME		180	/* seconds before peer times us out */
#define BGP_KEEPALIVE_TIME	60	/* seconds between messages */
#define BGP_STATE_TIME		60	/* state transition timeout in seconds */
#define BGP_MAX_RETRY		42	/* maximum number of times to retry */
#define BGP_RETRY_BACKOFF	60	/* number of seconds between retries,
					   cumulative */

#define BGP_METRIC		1	/* multi_exit_disc */
#define BGP_LOCAL_PREF		100	/* local preference value */

struct bgp_header {
    char marker[16];
    uint16_t len;
    uint8_t type;
} __attribute__ ((packed));

/* bgp_header.type */
#define BGP_MSG_OPEN		1
#define BGP_MSG_UPDATE		2
#define BGP_MSG_NOTIFICATION	3
#define BGP_MSG_KEEPALIVE	4

struct bgp_packet {
    struct bgp_header header;
    char data[BGP_MAX_PACKET_SIZE - sizeof(struct bgp_header)]; /* variable */
} __attribute__ ((packed));

struct bgp_data_open {
    uint8_t version;
#define BGP_VERSION	4
    uint16_t as;
    uint16_t hold_time;
    uint32_t identifier;
    uint8_t opt_len;
#define BGP_DATA_OPEN_SIZE	10 /* size of struct excluding opt_params */
    char opt_params[sizeof(((struct bgp_packet *)0)->data) - BGP_DATA_OPEN_SIZE]; /* variable */
} __attribute__ ((packed));

struct bgp_opt_param {
    uint8_t type;
    uint8_t len;
#define BGP_MAX_OPT_PARAM_SIZE	256
    char value[BGP_MAX_OPT_PARAM_SIZE];
} __attribute__ ((packed));

#define BGP_PARAM_TYPE_CAPABILITY	2
struct bgp_capability {
    uint8_t code;
    uint8_t len;
#define BGP_MAX_CAPABILITY_SIZE	256
    char value[BGP_MAX_CAPABILITY_SIZE];
} __attribute__ ((packed));

/* RFC4760 Multiprotocol extension */
#define BGP_CAP_CODE_MP	1

struct bgp_mp_cap_param {
    uint16_t afi; /* sa_family_t */
    uint8_t reserved; /* SHOULD be 0 */
    uint8_t safi;
} __attribute__ ((packed));

/* bgp_mp_cap_param.afi */
#define BGP_MP_AFI_RESERVED	0
#define BGP_MP_AFI_IPv4		1
#define BGP_MP_AFI_IPv6		2
/* bgp_mp_cap_param.safi */
#define BGP_MP_SAFI_UNICAST	1
#define BGP_MP_SAFI_MULTICAST	2

struct bgp_ip6_prefix {
    uint8_t len;
    uint8_t prefix[16]; /* variable */
} __attribute__ ((packed));

/* end of RFC4760 specific definitions */

struct bgp_ip_prefix {
    uint8_t len;
    uint32_t prefix; /* variable */
} __attribute__ ((packed));

/* works for both IPv4 and IPv6 prefixes */
#define BGP_IP_PREFIX_SIZE(p) (1 + ((p).len / 8) + ((p).len % 8 != 0))

struct bgp_path_attr {
    uint8_t flags;
    uint8_t code;
    union {
	struct {
	    uint8_t len;
	    char value[29];		/* semi-random size, adequate for l2tpns */
	} __attribute__ ((packed)) s;	/* short */
	struct {
	    uint16_t len;
	    char value[28];
	} __attribute__ ((packed)) e;	/* extended */
    } data; /* variable */
} __attribute__ ((packed));

struct bgp_attr_mp_reach_nlri_partial {
    uint16_t afi; /* sa_family_t */
    uint8_t safi;
    uint8_t next_hop_len;
    uint8_t next_hop[16];
    uint8_t reserved;
} __attribute__ ((packed));
#define BGP_PATH_ATTR_MP_REACH_NLRI_PARTIAL_SIZE (3 + sizeof(struct bgp_attr_mp_reach_nlri_partial))

struct bgp_attr_mp_unreach_nlri_partial {
    uint16_t afi; /* sa_family_t */
    uint8_t safi;
} __attribute__ ((packed));
/* we use it as an extended attribute */
#define BGP_PATH_ATTR_MP_UNREACH_NLRI_PARTIAL_SIZE (4 + sizeof(struct bgp_attr_mp_unreach_nlri_partial))

/* bgp_path_attr.flags (bitfields) */
#define BGP_PATH_ATTR_FLAG_OPTIONAL	(1 << 7)
#define BGP_PATH_ATTR_FLAG_TRANS	(1 << 6)
#define BGP_PATH_ATTR_FLAG_PARTIAL	(1 << 5)
#define BGP_PATH_ATTR_FLAG_EXTLEN	(1 << 4)

/* bgp_path_attr.code, ...value */
#define BGP_PATH_ATTR_CODE_ORIGIN		1	/* well-known, mandatory */
#  define BGP_PATH_ATTR_CODE_ORIGIN_IGP		  0
#  define BGP_PATH_ATTR_CODE_ORIGIN_EGP		  1
#  define BGP_PATH_ATTR_CODE_ORIGIN_INCOMPLETE	  2
#define BGP_PATH_ATTR_CODE_AS_PATH		2	/* well-known, mandatory */
#  define BGP_PATH_ATTR_CODE_AS_PATH_AS_SET	  1
#  define BGP_PATH_ATTR_CODE_AS_PATH_AS_SEQUENCE  2
#define BGP_PATH_ATTR_CODE_NEXT_HOP		3	/* well-known, mandatory */
#define BGP_PATH_ATTR_CODE_MULTI_EXIT_DISC	4	/* optional, non-transitive */
#define BGP_PATH_ATTR_CODE_LOCAL_PREF		5	/* well-known, discretionary */
#define BGP_PATH_ATTR_CODE_ATOMIC_AGGREGATE	6	/* well-known, discretionary */
#define BGP_PATH_ATTR_CODE_AGGREGATOR		7	/* optional, transitive */
#define BGP_PATH_ATTR_CODE_COMMUNITIES		8	/* optional, transitive (RFC1997) */
#define BGP_PATH_ATTR_CODE_MP_REACH_NLRI	14	/* optional, non-transitive (RFC4760) */
#define BGP_PATH_ATTR_CODE_MP_UNREACH_NLRI	15	/* optional, non-transitive (RFC4760) */

#define BGP_PATH_ATTR_SIZE(p) ((((p).flags & BGP_PATH_ATTR_FLAG_EXTLEN) \
    ? ((p).data.e.len + 4) : (p).data.s.len) + 3)

/* well known COMMUNITIES */
#define BGP_COMMUNITY_NO_EXPORT			0xffffff01	/* don't advertise outside confederation */
#define BGP_COMMUNITY_NO_ADVERTISE		0xffffff02	/* don't advertise to any peer */
#define BGP_COMMUNITY_NO_EXPORT_SUBCONFED	0xffffff03	/* don't advertise to any other AS */

struct bgp_data_notification {
    uint8_t error_code;
    uint8_t error_subcode;
    char data[sizeof(((struct bgp_packet *)0)->data) - 2]; /* variable */
} __attribute__ ((packed));

/* bgp_data_notification.error_code, .error_subcode */
#define BGP_ERR_UNSPEC			0
#define BGP_ERR_HEADER			1
#  define BGP_ERR_HDR_NOT_SYNC		  1
#  define BGP_ERR_HDR_BAD_LEN		  2
#  define BGP_ERR_HDR_BAD_TYPE		  3
#define BGP_ERR_OPEN			2
#  define BGP_ERR_OPN_VERSION		  1
#  define BGP_ERR_OPN_BAD_AS		  2
#  define BGP_ERR_OPN_BAD_IDENT		  3
#  define BGP_ERR_OPN_UNSUP_PARAM	  4
#  define BGP_ERR_OPN_AUTH_FAILURE	  5
#  define BGP_ERR_OPN_HOLD_TIME		  6
#  define BGP_ERR_OPN_UNSUP_CAP		  7
#define BGP_ERR_UPDATE			3
#  define BGP_ERR_UPD_BAD_ATTR_LIST	  1
#  define BGP_ERR_UPD_UNKN_WK_ATTR	  2
#  define BGP_ERR_UPD_MISS_WK_ATTR	  3
#  define BGP_ERR_UPD_BAD_ATTR_FLAG	  4
#  define BGP_ERR_UPD_BAD_ATTR_LEN	  5
#  define BGP_ERR_UPD_BAD_ORIGIN	  6
#  define BGP_ERR_UPD_ROUTING_LOOP	  7
#  define BGP_ERR_UPD_BAD_NEXT_HOP	  8
#  define BGP_ERR_UPD_BAD_OPT_ATTR	  9
#  define BGP_ERR_UPD_BAD_NETWORK	  10
#  define BGP_ERR_UPD_BAD_AS_PATH	  11
#define BGP_ERR_HOLD_TIMER_EXP		4
#define BGP_ERR_FSM			5
#define BGP_ERR_CEASE			6

enum bgp_state {
    Disabled,				/* initial, or failed */
    Idle,				/* trying to connect */
    Connect,				/* connect issued */
    Active,				/* connected, waiting to send OPEN */
    OpenSent,				/* OPEN sent, waiting for peer OPEN */
    OpenConfirm,			/* KEEPALIVE sent, waiting for peer KEEPALIVE */
    Established,			/* established */
};

struct bgp_route6_list {
    struct bgp_ip6_prefix dest;
    struct bgp_route6_list *next;
};

struct bgp_route_list {
    struct bgp_ip_prefix dest;
    struct bgp_route_list *next;
};

struct bgp_buf {
    struct bgp_packet packet;		/* BGP packet */
    size_t done;			/* bytes sent/recvd */
};

enum bgp_mp_handling {
    HandleIPv6Routes,
    DoesntHandleIPv6Routes,
    HandlingUnknown,
};

/* state */
struct bgp_peer {
    char name[32];			/* peer name */
    in_addr_t addr;			/* peer address */
    in_addr_t source_addr;		/* our source address */
    int as;				/* AS number */
    int sock;
    enum bgp_state state;		/* FSM state */
    enum bgp_state next_state;		/* next state after outbuf cleared */
    time_t state_time;			/* time of last state change */
    time_t keepalive_time;		/* time to send next keepalive */
    time_t retry_time;			/* time for connection retry */
    int retry_count;			/* connection retry count */
    int init_keepalive;			/* initial keepalive time */
    int init_hold;			/* initial hold time */
    int keepalive;			/* negotiated keepalive time */
    int hold;				/* negotiated hold time */
    time_t expire_time;			/* time next peer packet expected */
    int routing;			/* propagate routes */
    int update_routes;			/* UPDATE required */
    struct bgp_route_list *routes;	/* routes known by this peer */
    struct bgp_buf *outbuf;		/* pending output */
    struct bgp_buf *inbuf;		/* pending input */
    int cli_flag;			/* updates requested from CLI */
    char *path_attrs;			/* path attrs to send in UPDATE message */
    int path_attr_len;			/* length of path attrs */
    int path_attr_len_without_nexthop;	/* length of path attrs  without NEXT_HOP */
    uint32_t events;			/* events to poll */
    struct event_data edata;		/* poll data */
    enum bgp_mp_handling mp_handling;	/* how it handles IPv6 routes advertisements */
    int update_routes6;			/* UPDATE required for IPv6 routes */
    struct bgp_route6_list *routes6;	/* IPv6 routes known by this peer */
    char mp_reach_nlri_partial[BGP_PATH_ATTR_MP_REACH_NLRI_PARTIAL_SIZE];
    char mp_unreach_nlri_partial[BGP_PATH_ATTR_MP_UNREACH_NLRI_PARTIAL_SIZE];
};

/* bgp_peer.cli_flag */
#define BGP_CLI_SUSPEND		1
#define BGP_CLI_ENABLE		2
#define BGP_CLI_RESTART		3

extern struct bgp_peer *bgp_peers;
extern int bgp_configured;

/* actions */
int bgp_setup(int as);
int bgp_start(struct bgp_peer *peer, char *name, int as, int keepalive,
    int hold, struct in_addr update_source, int enable);

void bgp_stop(struct bgp_peer *peer);
void bgp_halt(struct bgp_peer *peer);
int bgp_restart(struct bgp_peer *peer);
int bgp_add_route(in_addr_t ip, int prefixlen);
int bgp_add_route6(struct in6_addr ip, int prefixlen);
int bgp_del_route(in_addr_t ip, int prefixlen);
int bgp_del_route6(struct in6_addr ip, int prefixlen);
void bgp_enable_routing(int enable);
int bgp_set_poll(void);
int bgp_process(uint32_t events[]);
void bgp_process_peers_timers();
char const *bgp_state_str(enum bgp_state state);

#endif /* __BGP_H__ */
