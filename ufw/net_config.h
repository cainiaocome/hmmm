#ifndef _UFW_NET_CONFIG_H
#define _UFW_NET_CONFIG_H

#if __linux__

#	ifdef _BSD_SOURCE
#		undef _BSD_SOURCE
#		define _BSD_SOURCE 1
#	else
#		define _BSD_SOURCE 1
#	endif

#	include <sys/types.h>
#	include <sys/socket.h>
#	include <netinet/ip.h>
#	include <netinet/tcp.h>
#	include <netinet/udp.h>
#	include <netinet/ip_icmp.h>
#	include <netinet/igmp.h>
#	include <arpa/inet.h>
#	include <netdb.h>

#elif __MINGW32__

#	define _WIN32_WINNT 0x0501

#	include <winsock2.h>
#	include <ws2tcpip.h>
# include <iphlpapi.h>
#	include <sys/param.h>

#	define	IPVERSION	4               /* IP version number */
#	define	IP_MAXPACKET	65535		/* maximum packet size */
/*
 * Definitions for IP type of service (ip_tos)
 */
#	define	IPTOS_TOS_MASK		0x1E
#	define	IPTOS_TOS(tos)		((tos) & IPTOS_TOS_MASK)
#	define	IPTOS_LOWDELAY		0x10
#	define	IPTOS_THROUGHPUT	0x08
#	define	IPTOS_RELIABILITY	0x04
#	define	IPTOS_LOWCOST		0x02

/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
#	define	IPTOS_PREC_MASK			0xe0
#	define	IPTOS_PREC(tos)                ((tos) & IPTOS_PREC_MASK)
#	define	IPTOS_PREC_NETCONTROL		0xe0
#	define	IPTOS_PREC_INTERNETCONTROL	0xc0
#	define	IPTOS_PREC_CRITIC_ECP		0xa0
#	define	IPTOS_PREC_FLASHOVERRIDE	0x80
#	define	IPTOS_PREC_FLASH		0x60
#	define	IPTOS_PREC_IMMEDIATE		0x40
#	define	IPTOS_PREC_PRIORITY		0x20
#	define	IPTOS_PREC_ROUTINE		0x00

struct ip {
#	if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#	endif
#	if BYTE_ORDER == BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#	endif
    u_char ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
#	define	IP_RF 0x8000			/* reserved fragment flag */
#	define	IP_DF 0x4000			/* dont fragment flag */
#	define	IP_MF 0x2000			/* more fragments flag */
#	define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_char ip_ttl;			/* time to live */
    u_char ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};

typedef	u_long tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
    u_short th_sport;		/* source port */
    u_short th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
#	if BYTE_ORDER == LITTLE_ENDIAN
    u_char th_x2:4;		/* (unused) */
    u_char th_off:4;		/* data offset */
#	endif
#	if BYTE_ORDER == BIG_ENDIAN
    u_char th_off:4;		/* data offset */
    u_char th_x2:4;		/* (unused) */
#	endif
    u_char th_flags;
#	define TH_FIN	0x01
#	define TH_SYN	0x02
#	define TH_RST	0x04
#	define TH_PUSH	0x08
#	define TH_ACK	0x10
#	define TH_URG	0x20
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};
#	define TCPOPT_EOL		0
#	define TCPOPT_NOP		1
#	define TCPOPT_MAXSEG		2
#	define TCPOLEN_MAXSEG		4
#	define TCPOPT_WINDOW		3
#	define TCPOLEN_WINDOW		3
#	define TCPOPT_SACK_PERMITTED	4		/* Experimental */
#	define TCPOLEN_SACK_PERMITTED	2
#	define TCPOPT_SACK		5		/* Experimental */
#	define TCPOPT_TIMESTAMP	8
#	define TCPOLEN_TIMESTAMP	10
#	define TCPOLEN_TSTAMP_APPA	(TCPOLEN_TIMESTAMP+2) /* appendix A */
struct udphdr {
  u_short uh_sport;		/* source port */
  u_short uh_dport;		/* destination port */
  u_short uh_ulen;		/* udp length */
  u_short uh_sum;		/* udp checksum */
};
struct icmphdr {
  u_char type;		/* message type */
  u_char code;		/* type sub-code */
  u_short checksum;
  union {
    struct {
      u_short	id;
      u_short	sequence;
    } echo;			/* echo datagram */
    u_long	gateway;	/* gateway address */
    struct {
      u_short	__unused;
      u_short	mtu;
    } frag;			/* path mtu discovery */
  } un;
};
struct igmp {
  u_char igmp_type;             /* IGMP type */
  u_char igmp_code;             /* routing code */
  u_short igmp_cksum;           /* checksum */
  struct in_addr igmp_group;      /* group address */
};

#endif /* __MINGW32__ */

#define TH_ECE 0x40
#define TH_CWR 0x80
#define IPV4_H 20
#define TCP_H 20
#define UDP_H 8


#endif /* _UFW_NET_CONFIG_H */
