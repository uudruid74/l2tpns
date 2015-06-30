/* L2TPLAC */
/* $Id: l2tplac.h,v 1.0 2012-07-01 14:49:28 fendo Exp $ */

#ifndef __L2TPLAC_H__
#define __L2TPLAC_H__

#define L2TPLACPORT	65432	// L2TP port for Remote LNS
// Limits
#define MAXRLNSTUNNEL	201

typedef uint16_t confrlnsidt;

// l2tplac.c
void lac_initremotelnsdata();
int lac_session_forward(uint8_t *buf, int len, sessionidt sess, uint16_t proto, in_addr_t s_addr, int sin_port, uint16_t indexudpfd);
int lac_conf_forwardtoremotelns(sessionidt s, char * puser);
void lac_calc_rlns_auth(tunnelidt t, uint8_t id, uint8_t *out);
int lac_addremotelns(char *mask, char *IP_RemoteLNS, char *Port_RemoteLNS, char *SecretRemoteLNS);

/* Function for Tunnels creating from radius reponses */
void lac_reset_rad_tag_tunnel_ctxt();
void lac_set_rad_tag_tunnel_type(uint8_t tag, uint32_t tunnel_type);
void lac_set_rad_tag_tunnel_medium_type(uint8_t tag, uint32_t tunnel_medium_type);
void lac_set_rad_tag_tunnel_serv_endpt(uint8_t tag, char *tunnel_server_endpoint);
void lac_set_rad_tag_tunnel_password(uint8_t tag, char *tunnel_password);
void lac_set_rad_tag_tunnel_assignment_id(uint8_t tag, char *tunnel_assignment_id);
void lac_save_rad_tag_tunnels(sessionidt s);
int lac_rad_select_assignment_id(sessionidt s, char *assignment_id);

int lac_rad_forwardtoremotelns(sessionidt s, char *assignment_id, char * puser);

int lac_cli_show_remotelns(confrlnsidt idrlns, char *strout);
#endif /* __L2TPLAC_H__ */
