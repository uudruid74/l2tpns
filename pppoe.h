
#ifndef __PPPOE_H__
#define __PPPOE_H__

#define DEFAULT_PPPOE_AC_NAME	"l2tpns-pppoe"

// pppoe.c
void init_pppoe(void);
void process_pppoe_disc(uint8_t *pack, int size);
void process_pppoe_sess(uint8_t *pack, int size);
void pppoe_sess_send(const uint8_t *pack, uint16_t l, tunnelidt t);
uint8_t *pppoe_makeppp(uint8_t *b, int size, uint8_t *p, int l, sessionidt s, tunnelidt t,
						uint16_t mtype, uint8_t prio, bundleidt bid, uint8_t mp_bits);
uint8_t *opt_pppoe_makeppp(uint8_t *p, int l, sessionidt s, tunnelidt t, uint16_t mtype, uint8_t prio, bundleidt bid, uint8_t mp_bits);
void pppoe_shutdown_session(sessionidt s);
void pppoe_forwardto_session_pppoe(uint8_t *pack, int size, sessionidt sess, uint16_t proto);
void pppoe_process_forward(uint8_t *pack, int size, in_addr_t addr);
void pppoe_send_garp();
char * get_string_codepad(uint8_t codepad);

extern int pppoediscfd;		// pppoe discovery socket
extern int pppoesessfd;	// pppoe session socket

#endif /* __PPPOE_H__ */
