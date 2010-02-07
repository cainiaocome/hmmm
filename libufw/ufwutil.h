#ifndef _UFWUTIL_H_
#define _UFWUTIL_H_

/*
	a wrapper for sending/receiving tcp/udp packets
*/

#include <sys/types.h>
#include "tcpdump.h"


#define PRINT_RECV     0x1
#define PRINT_SEND     0x2
#define PRINT_ALL      (PRINT_RECV | PRINT_SEND)
#define DUMP_RECV      0x4
#define DUMP_SEND      0x8
#define DUMP_ALL       (DUMP_RECV | DUMP_SEND)
#define FILTER_SADDR   0x10
#define FILTER_DADDR   0x20
#define FILTER_ADDR    (FILTER_SADDR | FILTER_DADDR)
#define FILTER_SPORT   0x40
#define FILTER_DPORT   0x80
#define FILTER_PORT    (FILTER_SPORT | FILTER_DPORT)
#define FILTER_CONN    (FILTER_ADDR | FILTER_PORT)
#define FATAL          0x100
#define DUMP_AUTONAME  0x200
#define SIGIO_MANUAL   0x400

#define HOOK_RECV   0
#define HOOK_SEND   1

#define FIN	0x01
#define SYN	0x02
#define RST	0x04
#define PSH	0x08
#define ACK	0x10
#define URG	0x20
#define ECE	0x40
#define CWR	0x80
#define ALL 0xff

#define	IP_RF 0x8000
#define	IP_DF 0x4000
#define	IP_MF 0x2000
#define	IP_OFFMASK 0x1fff
#define IP_MAXPACKET 65535

#define TCP 6
#define UDP 17

/* OPAQUE struct */
typedef struct _ufw_sk {
	int fd;
	struct node *recvhook;
	struct node *sendhook;
	int opts;
	u_int8_t ttl;
	u_int8_t proto;
	u_int32_t saddr;
	u_int32_t daddr;
	u_int16_t sport;
	u_int16_t dport;
	u_int16_t window;
	u_int8_t recvbuf[IP_MAXPACKET];
	u_int8_t sendbuf[IP_MAXPACKET];
	struct timeval first_packet;
	size_t limit_packet;
	u_int8_t limit_packet_flags;
	size_t limit_byte;
	int received;
	dump_t *dump;
} ufw_sk;


/**
 * ufw_hook type
 * @param ip the pointer to a valid ip packet
 * @param time timestamp of the packet
 * @param dir direction, 0 for incoming, 1 for outcoming
 * @param user
 * @return 1 or 0, whether to continue the hook list
 * note
 *   any hook function should NOT block.
 */
typedef int (*ufw_hook)(void *ip, const struct timeval *time, int dir, void *user);

/**
 * create a new ufw wrapper socket
 * @param protocol TCP or UDP
 * @param options 
 *            PRINT_RECV: print the received packets to stdout
 *            PRINT_SEND: print the packets to send to stdout
 *            PRINT_ALL: the above two
 *            DUMP_RECV: ...
 *            DUMP_SEND: ...
 *            DUMP_ALL: ...
 *            DUMP_AUTONAME: ...
 *            FILTER_SADDR: only receive packets to local _saddr_
 *            FILTER_DADDR: only receive packets from remote _daddr_
 *            FILTER_ADDR: the above two
 *            FILTER_SPORT: only receive packets to local _sport_
 *            FILTER_DPORT: only receive packets from remote _dport_
 *            FILTER_PORT: the above two
 *            FILTER_CONN: the above four
 *            FATAL: bark and exit on error
 * @return 0 for success, -1 for error
 */
ufw_sk *ufw_socket(int protocol, int options);
void ufw_close(ufw_sk *);

/**
 * insert or remove hook
 * @param whence: HOOK_RECV or HOOK_SEND
 * @param hk: pointer to a ufw_hook type function
 * @param user: user pointer passed to hook function
 * @return number of inserted or removed hooks, -1 for failure and errno set
 * note
 *   new hook is inserted into the head of the hook list.
 *   when a hook function return 0, the rest functions in the same
 *   hook chain will not be called.
 *
 *   so custom filter can be implemented through hook.
 */
int ufw_inserthook(ufw_sk *, int whence, ufw_hook hk, void *user);
int ufw_removehook(ufw_sk *, int whence, ufw_hook hk);

int ufw_connect(ufw_sk *, u_int32_t addr, u_int16_t port);
int ufw_set_source(ufw_sk *, u_int32_t addr, u_int16_t port);
int ufw_set_dest(ufw_sk *sk, u_int32_t addr, u_int16_t port);
int ufw_set_sport(ufw_sk *sk, u_int16_t port);
int ufw_set_dport(ufw_sk *sk, u_int16_t port);

int ufw_bindtodev(ufw_sk *sk, const char *name);
int ufw_set_dumpfile(ufw_sk *, const char *pathname);
int ufw_set_window(ufw_sk *, u_int16_t);
int ufw_set_ttl(ufw_sk *, u_int8_t);

/**
 * set sending limit by packets
 * @param limit packets per seconds, 0 to reset
 * @param flags limit by packets matching the flags  (tcp only)
 */
int ufw_set_limit_packet(ufw_sk *, int limit, int flags);
int ufw_set_limit_byte(ufw_sk *, int);//similar

/**
 * send a packet
 * params meaning obvious
 * @return bytes sent or -1 on error and errno set
 * note
 *   ufw_connect() or ufw_set_source() should be called prior to this function
 *   otherwise this function will return error
 */
int ufw_send_tcp(ufw_sk *, u_int8_t flags, u_int32_t seq, u_int32_t ack, const void *payload, int payload_size);
int ufw_send_udp(ufw_sk *, const void *payload, int payload_size);

u_int32_t ufw_atoh(const char *ip);

int ufw_pause(ufw_sk *);
int ufw_sleep(ufw_sk *sk, unsigned int seconds);

void dsleep(double seconds);

int ufw_repeat(ufw_sk *);
#endif /* _UFWUTIL_H_ */
