/*
 * Fernando ALVES 2013
 * Add functionality "LAC" to l2tpns.
 * Used to forward a ppp session to another "LNS".
 * GPL licenced
 */

#include <errno.h>
#include <string.h>
#include <netinet/ip6.h>

#include "md5.h"
#include "dhcp6.h"
#include "l2tpns.h"
#include "util.h"
#include "cluster.h"

#include "l2tplac.h"
#include "pppoe.h"

/* sequence diagram: Client <--> LAC <--> LNS1 <--> LNS2
 *
 *           LCP Negotiation
 * Client <-------------------> LAC
 *         Challenge (CHAP/PAP)
 * Client <-------------------> LAC
 *                                         SCCRQ
 *                              LAC --------------------> LNS1 (Tunnel Open)
 *                                         SCCRP
 *                              LAC <-------------------- LNS1 (Tunnel Open)
 *                                         SCCCN
 *                              LAC --------------------> LNS1 (Tunnel Open)
 *                                         ZLB
 *                              LAC <-------------------- LNS1 (Tunnel Open)
 *                                         ICRQ
 *                              LAC --------------------> LNS1 (Session Open)
 *                                         ICRP
 *                              LAC <-------------------- LNS1 (Session Open)
 *                                         ICCN
 *                              LAC --------------------> LNS1 (Session Open)
 *                                         ZLB
 *                              LAC <-------------------- LNS1 (Session Open)
 *                        LCP Negotiation
 * Client <---------------------------------------------> LNS1
 *                        Challenge (CHAP/PAP)
 * Client <---------------------------------------------> LNS1
 *                                                                    SCCRQ
 *                                                        LNS1 --------------------> LNS2 (Tunnel Open)
 *                                                                    SCCRP
 *                                                        LNS1 <-------------------- LNS2 (Tunnel Open)
 *                                                                    SCCCN
 *                                                        LNS1 --------------------> LNS2 (Tunnel Open)
 *                                                                    ZLB
 *                                                        LNS1 <-------------------- LNS2 (Tunnel Open)
 *                                                                    ICRQ
 *                                                        LNS1 --------------------> LNS2 (Session Open)
 *                                                                    ICRP
 *                                                        LNS1 <-------------------- LNS2 (Session Open)
 *                                                                    ICCN
 *                                                        LNS1 --------------------> LNS2 (Session Open)
 *                                                                    ZLB
 *                                                        LNS1 <-------------------- LNS2 (Session Open)
 *                                   LCP Negotiation
 * Client <------------------------------------------------------------------------> LNS2
 *                                   PAP/CHAP Authentification
 * Client <------------------------------------------------------------------------> LNS2
 *                                   DATA (ppp)
 * Client <------------------------------------------------------------------------> LNS2
 * */

typedef struct
{
	uint32_t tunnel_type;
	uint32_t tunnel_medium_type;
	in_addr_t tunnel_server_endpoint; /* IP remote LNS */
	char tunnel_password[64]; /* l2tpsecret remote LNS */
	char tunnel_assignment_id[256];
} tunnelrlnst;

// Max Radius Tunnels by remote LNS
#define MAXTAGTUNNEL	0x20
static tunnelrlnst ptunnelrlns[MAXTAGTUNNEL];

/*
 * Possible configrlns states
 * CONFRLNSFREE -> CONFRLNSSET -> CONFRLNSFREE
 */
enum
{
	CONFRLNSFREE = 0,	// Not in use
	CONFRLNSSET,		// Config Set
	CONFRLNSSETBYRADIUS	// Config Set
};

// struct remote lns
typedef struct
{
	int state;			// conf state (tunnelstate enum)
	in_addr_t ip;		// Ip for far end
	uint16_t port;		// port for far end
	hasht auth;			// request authenticator
	char strmaskuser[MAXUSER];
	char l2tp_secret[64];	// L2TP shared secret
	char tunnel_assignment_id[256];
}
configrlns;

configrlns *pconfigrlns = NULL;

// Init data structures
void lac_initremotelnsdata()
{
	confrlnsidt i;

	if ( !(pconfigrlns = shared_malloc(sizeof(pconfigrlns[0]) * MAXRLNSTUNNEL)) )
	{
		LOG(0, 0, 0, "Error doing malloc for tunnels lac: %s\n", strerror(errno));
		exit(1);
	}

	memset(pconfigrlns, 0, sizeof(pconfigrlns[0]) * MAXRLNSTUNNEL);

	// Mark all the conf as free.
	for (i = 1; i < MAXRLNSTUNNEL; i++)
		pconfigrlns[i].state = CONFRLNSFREE;	// mark it as not filled in.

	config->highest_rlnsid = 0;

	lac_reset_rad_tag_tunnel_ctxt();
}

// Reset Radius TAG tunnel context
void lac_reset_rad_tag_tunnel_ctxt()
{
	memset(ptunnelrlns, 0, sizeof(ptunnelrlns[0]) * MAXTAGTUNNEL);
}

// Add tunnel_type radius TAG tunnel to context
void lac_set_rad_tag_tunnel_type(uint8_t tag, uint32_t tunnel_type)
{
	if (tag < MAXTAGTUNNEL)
		ptunnelrlns[tag].tunnel_type = tunnel_type;
}

// Add tunnel_medium_type Radius TAG tunnel to context
void lac_set_rad_tag_tunnel_medium_type(uint8_t tag, uint32_t tunnel_medium_type)
{
	if (tag < MAXTAGTUNNEL)
		ptunnelrlns[tag].tunnel_medium_type = tunnel_medium_type;
}

// Add tunnel_server_endpoint Radius TAG tunnel to context
void lac_set_rad_tag_tunnel_serv_endpt(uint8_t tag, char *tunnel_server_endpoint)
{
	if (tag < MAXTAGTUNNEL)
	{
		ptunnelrlns[tag].tunnel_server_endpoint = ntohl(inet_addr(tunnel_server_endpoint));
	}
}

// Add tunnel_password Radius TAG tunnel to context
void lac_set_rad_tag_tunnel_password(uint8_t tag, char *tunnel_password)
{
	if ((tag < MAXTAGTUNNEL) && (strlen(tunnel_password) < 64))
	{
		strcpy(ptunnelrlns[tag].tunnel_password, tunnel_password);
	}
}

// Add tunnel_assignment_id Radius TAG tunnel to context
void lac_set_rad_tag_tunnel_assignment_id(uint8_t tag, char *tunnel_assignment_id)
{
	if ((tag < MAXTAGTUNNEL) && (strlen(tunnel_assignment_id) < 256))
	{
		strcpy(ptunnelrlns[tag].tunnel_assignment_id, tunnel_assignment_id);
	}
}

// Select a tunnel_assignment_id
int lac_rad_select_assignment_id(sessionidt s, char *assignment_id)
{
	int idtag;
	int nbtagfound = 0;
	int bufidtag[MAXTAGTUNNEL];

	for (idtag = 0; idtag < MAXTAGTUNNEL; ++idtag)
	{
		if (ptunnelrlns[idtag].tunnel_type == 0)
			continue;
		else if (ptunnelrlns[idtag].tunnel_type != 3) // 3 == L2TP tunnel type
			LOG(1, s, session[s].tunnel, "Error, Only L2TP tunnel type supported\n");
		else if (ptunnelrlns[idtag].tunnel_medium_type != 1)
			LOG(1, s, session[s].tunnel, "Error, Only IP tunnel medium type supported\n");
		else if (ptunnelrlns[idtag].tunnel_server_endpoint == 0)
			LOG(1, s, session[s].tunnel, "Error, Bad IP tunnel server endpoint \n");
		else if (strlen(ptunnelrlns[idtag].tunnel_assignment_id) > 0)
		{
			bufidtag[nbtagfound] = idtag;
			nbtagfound++;
		}
	}

	if (nbtagfound > 0)
	{
		// random between 0 and nbtagfound-1
		idtag = (rand() % nbtagfound);

		if (idtag >= nbtagfound)
			idtag = 0; //Sanity checks.

		strcpy(assignment_id, ptunnelrlns[bufidtag[idtag]].tunnel_assignment_id);
		return 1;
	}

	// Error no tunnel_assignment_id found
	return 0;
}

// Save the 'radius tag tunnels' context on global configuration
void lac_save_rad_tag_tunnels(sessionidt s)
{
	confrlnsidt idrlns;
	int idtag;

	for (idtag = 0; idtag < MAXTAGTUNNEL; ++idtag)
	{
		if (ptunnelrlns[idtag].tunnel_type == 0)
			continue;
		else if (ptunnelrlns[idtag].tunnel_type != 3) // 3 == L2TP tunnel type
			LOG(1, s, session[s].tunnel, "Error, Only L2TP tunnel type supported\n");
		else if (ptunnelrlns[idtag].tunnel_medium_type != 1)
			LOG(1, s, session[s].tunnel, "Error, Only IP tunnel medium type supported\n");
		else if (ptunnelrlns[idtag].tunnel_server_endpoint == 0)
			LOG(1, s, session[s].tunnel, "Error, Bad IP tunnel server endpoint \n");
		else if (strlen(ptunnelrlns[idtag].tunnel_assignment_id) <= 0)
			LOG(1, s, session[s].tunnel, "Error, No tunnel_assignment_id \n");
		else if (ptunnelrlns[idtag].tunnel_server_endpoint == ntohl(config->bind_address))
			LOG(0, s, session[s].tunnel, "Error, IP Remote LNS == IP local bind address (%s) !!!\n", fmtaddr(config->bind_address, 0));
		else
		{
			for (idrlns = 1; idrlns < MAXRLNSTUNNEL; ++idrlns)
			{
				if (pconfigrlns[idrlns].state == CONFRLNSFREE)
				{
					pconfigrlns[idrlns].ip = ptunnelrlns[idtag].tunnel_server_endpoint;
					pconfigrlns[idrlns].port = L2TPPORT; //Default L2TP port
					strcpy(pconfigrlns[idrlns].l2tp_secret, ptunnelrlns[idtag].tunnel_password);
					strcpy(pconfigrlns[idrlns].tunnel_assignment_id, ptunnelrlns[idtag].tunnel_assignment_id);

					config->highest_rlnsid = idrlns;

					pconfigrlns[idrlns].state = CONFRLNSSETBYRADIUS;

					break;
				}
				else if (pconfigrlns[idrlns].state == CONFRLNSSETBYRADIUS)
				{
					if ( (pconfigrlns[idrlns].ip == ptunnelrlns[idtag].tunnel_server_endpoint) &&
						 (strcmp(pconfigrlns[idrlns].tunnel_assignment_id, ptunnelrlns[idtag].tunnel_assignment_id) == 0) )
					{
						// l2tp_secret may be changed
						strcpy(pconfigrlns[idrlns].l2tp_secret, ptunnelrlns[idtag].tunnel_password);
						pconfigrlns[idrlns].port = L2TPPORT; //Default L2TP poart

						if (config->highest_rlnsid < idrlns) config->highest_rlnsid = idrlns;

						break;
					}
				}
			}

			if (idrlns >= MAXRLNSTUNNEL)
			{
				LOG(0, s, session[s].tunnel, "No more Remote LNS Conf Free\n");
				return;
			}
		}
	}
}

// Create Remote LNS a Tunnel or Session
static int lac_create_tunnelsession(tunnelidt t, sessionidt s, confrlnsidt i_conf, char * puser)
{
	if (t == 0)
	{
		if (main_quit == QUIT_SHUTDOWN) return 0;

		// Start Open Tunnel
		if (!(t = lac_new_tunnel()))
		{
			LOG(1, 0, 0, "No more tunnels\n");
			STAT(tunnel_overflow);
			return 0;
		}
		lac_tunnelclear(t);
		tunnel[t].ip = pconfigrlns[i_conf].ip;
		tunnel[t].port = pconfigrlns[i_conf].port;
		tunnel[t].window = 4; // default window
		tunnel[t].isremotelns = i_conf;
		tunnel[t].indexudp = config->indexlacudpfd;
		STAT(tunnel_created);

		random_data(pconfigrlns[i_conf].auth, sizeof(pconfigrlns[i_conf].auth));

		LOG(2, 0, t, "Create New tunnel to REMOTE LNS %s for user %s\n", fmtaddr(htonl(tunnel[t].ip), 0), puser);
		lac_send_SCCRQ(t, pconfigrlns[i_conf].auth, sizeof(pconfigrlns[i_conf].auth));
	}
	else if (tunnel[t].state == TUNNELOPEN)
	{
		if (main_quit != QUIT_SHUTDOWN)
		{

			/**********************/
			/** Open New session **/
			/**********************/
			sessionidt new_sess = sessionfree;

			sessionfree = session[new_sess].next;
			memset(&session[new_sess], 0, sizeof(session[new_sess]));

			if (new_sess > config->cluster_highest_sessionid)
				config->cluster_highest_sessionid = new_sess;

			session[new_sess].opened = time_now;
			session[new_sess].tunnel = t;
			session[new_sess].last_packet = session[s].last_data = time_now;

			session[new_sess].ppp.phase = Establish;
			session[new_sess].ppp.lcp = Starting;
			session[s].ppp.phase = Establish;

			LOG(2, 0, t, "Open New session to REMOTE LNS %s for user: %s\n", fmtaddr(htonl(tunnel[t].ip), 0), puser);
			// Sent ICRQ  Incoming-call-request
			lac_send_ICRQ(t, new_sess);

			// Set session to forward to another LNS
			session[s].forwardtosession = new_sess;
			session[new_sess].forwardtosession = s;
			strncpy(session[s].user, puser, sizeof(session[s].user) - 1);
			strncpy(session[new_sess].user, puser, sizeof(session[new_sess].user) - 1);

			STAT(session_created);
		}
		else
		{
			lac_tunnelshutdown(t, "Shutting down", 6, 0, 0);
		}
	}
	else
	{
		/** TODO **/
		LOG(1, 0, t, "(REMOTE LNS) tunnel is not open\n");
	}

	return 1;
}
// Check if session must be forwarded to another LNS
// return 1 if the session must be forwarded (and Creating a tunnel/session has been started)
//			else 0.
// Note: check from the configuration read on the startup-config (see setforward)
int lac_conf_forwardtoremotelns(sessionidt s, char * puser)
{
	tunnelidt t, j;
	confrlnsidt i;

	for (i = 1; i <= config->highest_rlnsid ; ++i)
	{
		if ( (pconfigrlns[i].state == CONFRLNSSET) && (NULL != strstr(puser, pconfigrlns[i].strmaskuser)) )
		{
			t = 0;
			for (j = 0; j <= config->cluster_highest_tunnelid ; ++j)
			{
				if ((tunnel[j].isremotelns) &&
					(tunnel[j].ip == pconfigrlns[i].ip) &&
					(tunnel[j].port == pconfigrlns[i].port) &&
					(tunnel[j].state != TUNNELDIE))
				{
					t = j;
					if (tunnel[t].isremotelns != i)
					{
						if ( (tunnel[t].state == TUNNELOPEN) || (tunnel[t].state == TUNNELOPENING) )
						{
							LOG(1, 0, t, "Tunnel Remote LNS ID inconsistency (IP RLNS:%s)\n",
								fmtaddr(htonl(pconfigrlns[i].ip), 0));

							tunnel[t].isremotelns = i;
						}
						else t = 0;
					}
					break;
				}
			}

			return lac_create_tunnelsession(t, s, i, puser);
		}
	}

	return 0;
}

// return 1 if the session must be forwarded (and Creating a tunnel/session has been started)
//			else 0.
// Note: Started from a radius response
int lac_rad_forwardtoremotelns(sessionidt s, char *assignment_id, char * puser)
{
	tunnelidt t, j;
	confrlnsidt i;

	for (i = 1; i <= config->highest_rlnsid ; ++i)
	{
		if ((pconfigrlns[i].state == CONFRLNSSETBYRADIUS) &&
			(strcmp(pconfigrlns[i].tunnel_assignment_id, assignment_id) == 0))
		{
			t = 0;
			for (j = 1; j <= config->cluster_highest_tunnelid ; ++j)
			{
				if ((tunnel[j].isremotelns == i) &&
					(tunnel[j].ip == pconfigrlns[i].ip) &&
					(tunnel[j].port == pconfigrlns[i].port) &&
					(tunnel[j].state != TUNNELDIE))
				{
					if ( (tunnel[j].state == TUNNELOPEN) ||
					     (tunnel[j].state == TUNNELOPENING) )
					{
						t = j;
						LOG(3, 0, t, "Tunnel Remote LNS already open(ing) (RLNS IP:%s)\n", fmtaddr(htonl(pconfigrlns[i].ip), 0));
						break;
					}
				}
			}

			return lac_create_tunnelsession(t, s, i, puser);
		}
	}

	return 0;
}

// Calcul the remote LNS auth
void lac_calc_rlns_auth(tunnelidt t, uint8_t id, uint8_t *out)
{
	MD5_CTX ctx;
	confrlnsidt idrlns;

	idrlns = tunnel[t].isremotelns;

	MD5_Init(&ctx);
	MD5_Update(&ctx, &id, 1);
	MD5_Update(&ctx, pconfigrlns[idrlns].l2tp_secret, strlen(pconfigrlns[idrlns].l2tp_secret));
	MD5_Update(&ctx, pconfigrlns[idrlns].auth, 16);
	MD5_Final(out, &ctx);
}

// Forward session to LAC or Remote LNS
int lac_session_forward(uint8_t *buf, int len, sessionidt sess, uint16_t proto, in_addr_t s_addr, int sin_port, uint16_t indexudpfd)
{
	uint16_t t = 0, s = 0;
	uint8_t *p = buf + 2; // First word L2TP options

	s = session[sess].forwardtosession;
	if (session[s].forwardtosession != sess)
	{
		LOG(0, sess, session[sess].tunnel, "Link Session (%u) broken\n", s);
		return 0;
	}

	t = session[s].tunnel;
	if (t >= MAXTUNNEL)
	{
		LOG(1, s, t, "Session with invalid tunnel ID\n");
		return 0;
	}

	if ((!tunnel[t].isremotelns) && (!tunnel[session[sess].tunnel].isremotelns))
	{
		LOG(0, sess, session[sess].tunnel, "Link Tunnel Session (%u/%u) broken\n", s, t);
		return 0;
	}

	if (!config->cluster_iam_master)
	{
		if ( (proto == PPPIPCP) || (proto == PPPLCP) ||
			 (proto == PPPPAP) || (proto == PPPCHAP) ||
			 (proto == PPPIPV6CP && config->ipv6_prefix.s6_addr[0]) ||
			 (proto == PPPCCP) )
		{
			session[sess].last_packet = time_now;
			master_forward_packet(buf, len, s_addr, sin_port, indexudpfd);
			return 1;
		}
	}

	if (t == TUNNEL_ID_PPPOE)
	{
		pppoe_forwardto_session_pppoe(buf, len, sess, proto);
		return 1;
	}

	if (*buf & 0x40)
	{	// length
		p += 2;
	}

	*(uint16_t *) p = htons(tunnel[t].far); // tunnel
	p += 2;
	*(uint16_t *) p = htons(session[s].far); // session
	p += 2;

	if (*buf & 0x08)
	{   // ns/nr
		*(uint16_t *) p = htons(tunnel[t].ns); // sequence
		p += 2;
		*(uint16_t *) p = htons(tunnel[t].nr); // sequence
		p += 2;
	}

	if ((proto == PPPIP) || (proto == PPPMP) ||(proto == PPPIPV6 && config->ipv6_prefix.s6_addr[0]))
	{
		session[sess].last_packet = session[sess].last_data = time_now;
		// Update STAT IN
		increment_counter(&session[sess].cin, &session[sess].cin_wrap, len);
		session[sess].cin_delta += len;
		session[sess].pin++;
		sess_local[sess].cin += len;
		sess_local[sess].pin++;

		session[s].last_data = time_now;
		// Update STAT OUT
		increment_counter(&session[s].cout, &session[s].cout_wrap, len); // byte count
		session[s].cout_delta += len;
		session[s].pout++;
		sess_local[s].cout += len;
		sess_local[s].pout++;
	}
	else
		session[sess].last_packet = time_now;

	tunnelsend(buf, len, t); // send it...

	return 1;
}

// Add new Remote LNS from CLI
// return:
//		 0 = Error
//		 1 = New Remote LNS conf ADD
//		 2 = Remote LNS Conf Updated
int lac_addremotelns(char *mask, char *IP_RemoteLNS, char *Port_RemoteLNS, char *SecretRemoteLNS)
{
	confrlnsidt idrlns;

	for (idrlns = 1; idrlns < MAXRLNSTUNNEL; ++idrlns)
	{
		if (pconfigrlns[idrlns].state == CONFRLNSFREE)
		{
			snprintf((char *) pconfigrlns[idrlns].strmaskuser, sizeof(pconfigrlns[idrlns].strmaskuser), "%s", mask);
			pconfigrlns[idrlns].ip = ntohl(inet_addr(IP_RemoteLNS));
			pconfigrlns[idrlns].port = atoi(Port_RemoteLNS);
			snprintf((char *) pconfigrlns[idrlns].l2tp_secret, sizeof(pconfigrlns[idrlns].l2tp_secret), "%s", SecretRemoteLNS);

			config->highest_rlnsid = idrlns;

			pconfigrlns[idrlns].state = CONFRLNSSET;

			return 1;
		}
		else if ((pconfigrlns[idrlns].state == CONFRLNSSET) && (strcmp(pconfigrlns[idrlns].strmaskuser, mask) == 0))
		{
			if ( (pconfigrlns[idrlns].ip != ntohl(inet_addr(IP_RemoteLNS))) ||
				 (pconfigrlns[idrlns].port != atoi(Port_RemoteLNS)) ||
				 (strcmp(pconfigrlns[idrlns].l2tp_secret, SecretRemoteLNS) != 0) )
			{
				memset(&pconfigrlns[idrlns], 0, sizeof(pconfigrlns[idrlns]));
				snprintf((char *) pconfigrlns[idrlns].strmaskuser, sizeof(pconfigrlns[idrlns].strmaskuser), "%s", mask);
				pconfigrlns[idrlns].ip = ntohl(inet_addr(IP_RemoteLNS));
				pconfigrlns[idrlns].port = atoi(Port_RemoteLNS);
				snprintf((char *) pconfigrlns[idrlns].l2tp_secret, sizeof(pconfigrlns[idrlns].l2tp_secret), "%s", SecretRemoteLNS);

				if (config->highest_rlnsid < idrlns) config->highest_rlnsid = idrlns;

				pconfigrlns[idrlns].state = CONFRLNSSET;
				// Conf Updated, the tunnel must be dropped
				return 2;
			}

			return 1;
		}
	}

	LOG(0, 0, 0, "No more Remote LNS Conf Free\n");

	return 0;
}

// Cli Show remote LNS defined
int lac_cli_show_remotelns(confrlnsidt idrlns, char *strout)
{
	if (idrlns > config->highest_rlnsid)
		return 0;

	if (idrlns == 0)
		// Show Summary
		sprintf(strout, "%15s %3s  %-32s %-32s %11s %7s %10s",
				"IP Remote LNS",
				"TID",
				"l2tp secret",
				"assignment Id",
				"File/Radius",
				"State",
				"Count Sess");
	else
	{
		tunnelidt t, tfound = 0;
		sessionidt s;
		int countsess = 0;
		char state[20];

		strcpy(state, "Close");
		for (t = 0; t <= config->cluster_highest_tunnelid ; ++t)
		{
			if ((tunnel[t].isremotelns == idrlns) &&
				(tunnel[t].ip == pconfigrlns[idrlns].ip) &&
				(tunnel[t].port == pconfigrlns[idrlns].port) &&
				(tunnel[t].state != TUNNELDIE))
			{
				if (tunnel[t].state == TUNNELOPENING)
					strcpy(state, "Opening");
				else if (tunnel[t].state == TUNNELOPEN)
					strcpy(state, "Open");

				for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
					if (session[s].tunnel == t)
						countsess++;
				tfound = t;
				break;
			}
		}

		sprintf(strout, "%15s %3u  %-32s %-32s %11s %7s %10u",
				fmtaddr(htonl(pconfigrlns[idrlns].ip), 0),
				tfound,
				pconfigrlns[idrlns].l2tp_secret,
				pconfigrlns[idrlns].tunnel_assignment_id,
				(pconfigrlns[idrlns].state == CONFRLNSSET?"File":(pconfigrlns[idrlns].state == CONFRLNSSETBYRADIUS?"Radius":"Free")),
				state,
				countsess);
	}

	return 1;
}
