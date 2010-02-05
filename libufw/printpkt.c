#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "cksum.h"
#include "fingerprint.h"

#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
#define FIN	0x01
#define SYN	0x02
#define RST	0x04
#define PSH	0x08
#define ACK	0x10
#define URG	0x20
#define ECE	0x40
#define CWR	0x80


struct ipinfo {
	u_int8_t proto;
	u_int8_t ttl;
	u_int16_t id;
	char id_str[20];
	char frag;
	char frag_str[20];
	u_int32_t laddr, raddr;
	u_int32_t saddr, daddr;
	char laddr_str[20], raddr_str[20];
	char *saddr_str, *daddr_str;
	char dir;
	char an[1000];
};

static inline int ip_preformat(struct ipinfo *ii, const void *buf, int dir){
	const struct iphdr *ip = buf;
	int off;
	char *a = ii->an;

	ii->an[0] = 0;
	ii->proto = ip->protocol;
	ii->ttl = ip->ttl;
	ii->id = ntohs(ip->id);
	if(dir && !ii->id)
		strcpy(ii->id_str, "auto");
	else
		snprintf(ii->id_str, 20, "%u", ii->id);

	off = ntohs(ip->frag_off);
	if(off & IP_RF){
		ii->frag = 'V';
		strcpy(ii->frag_str, "rsrv");
	}else if(off & IP_DF){
		ii->frag = 'D';
		strcpy(ii->frag_str, "dont");
	}else if(off & IP_MF){
		ii->frag = 'M';
		strcpy(ii->frag_str, "more");
	}else{
		ii->frag = '/';
		strcpy(ii->frag_str, "none");
	}

	ii->saddr = ntohl(ip->saddr);
	ii->daddr = ntohl(ip->daddr);
	ii->laddr = (dir?ii->saddr:ii->daddr);
	ii->raddr = (dir?ii->daddr:ii->saddr);

	strcpy(ii->laddr_str, 
		inet_ntoa(*(struct in_addr *)(dir?&ip->saddr:&ip->daddr)));
	strcpy(ii->raddr_str, 
		inet_ntoa(*(struct in_addr *)(dir?&ip->daddr:&ip->saddr)));

	ii->dir = (dir ? '>' : '<');

	return 1;
}

struct tcpinfo {
	char errstr[100];
	u_int16_t sport, dport;
	u_int16_t lport, rport;
	u_int32_t seq, ack;
	u_int16_t window;
	int optlen;
	char flags[10];
	char an[1000];
	int alen;
};
static inline int tcp_preformat(struct tcpinfo *ti, const void *buf, int dir){
	const struct iphdr *ip = buf;
	const struct tcphdr *tcp = buf + (ip->ihl << 2);
	int tlen = ntohs(ip->tot_len) - (ip->ihl << 2);
	char *a = ti->an;
	int i = 0;
	int flags = *(u_int8_t *)(buf + (ip->ihl << 2) + 13);
	char *gfwstr;

	ti->an[0] = 0;

	ti->sport = ntohs(tcp->source);
	ti->dport = ntohs(tcp->dest);
	ti->lport = (dir?ti->sport:ti->dport);
	ti->rport = (dir?ti->dport:ti->sport);
	ti->seq = ntohl(tcp->seq);
	ti->ack = ntohl(tcp->ack_seq);
	ti->window = ntohs(tcp->window);
	ti->optlen = (tcp->doff << 2) - sizeof(struct tcphdr);
	if(flags & FIN)ti->flags[i++]='F';
	if(flags & SYN)ti->flags[i++]='S';
	if(flags & RST)ti->flags[i++]='R';
	if(flags & PSH)ti->flags[i++]='P';
	if(flags & ACK)ti->flags[i++]='A';
	if(flags & URG)ti->flags[i++]='U';
	if(flags & ECE)ti->flags[i++]='E';
	if(flags & CWR)ti->flags[i++]='C';
	if(!i)ti->flags[i++]='_';
	ti->flags[i] = 0;
	ti->alen = tlen - (tcp->doff << 2);

	if(tcp->res1)
		a += sprintf(a, " res=%u", tcp->res1);
	if(tcp->urg_ptr)
		a += sprintf(a, " urg=%u", ntohs(tcp->urg_ptr));
	if(!dir && tcp->check != tcp_cksum(buf, tlen))
		a += sprintf(a, " ckerr=1");

	return 1;
}

struct udpinfo {
	char errstr[100];
	u_int16_t sport, dport;
	u_int16_t lport, rport;
	char an[1000];
	int alen;
};
static inline int udp_preformat(struct udpinfo *ui, const void *buf, int dir){
	const struct iphdr *ip = buf;
	const struct udphdr *udp = buf + (ip->ihl << 2);
	int tlen = ntohs(ip->tot_len) - (ip->ihl << 2);
	char *a = ui->an;
	char *gfwstr;
	
	ui->an[0] = 0;
	if((size_t)tlen < sizeof(struct udphdr)){
		snprintf(ui->errstr, 20, "udp=%u", tlen);
		return 0;
	}

	ui->sport = ntohs(udp->source);
	ui->dport = ntohs(udp->dest);
	ui->lport = (dir?ui->sport:ui->dport);
	ui->rport = (dir?ui->dport:ui->sport);
	ui->alen = tlen - sizeof(struct udphdr);


	return 1;
}



int packet_snprint_short(char *s, size_t len, const void *ip, 
                         const struct timeval *t, int dir, const void *_){
	(void)_;
	(void)t;
	struct ipinfo ii;
	ip_preformat(&ii, ip, dir);
	if(ii.proto == IPPROTO_TCP){
		struct tcpinfo ti;
		if(tcp_preformat(&ti, ip, dir)){
			return snprintf(s, len,
				"%u %s %c"
				" :%u%c%s:%u"
				" %s %u:%u %u|%u"
				"%s%s",
				ii.ttl, ii.id_str, ii.frag,
				ti.lport, ii.dir, ii.raddr_str, ti.rport,
				ti.flags, ti.seq, ti.ack, ti.window, ti.alen,
				ti.an, ii.an);
		}else{
			return snprintf(s, len,
				"%u %s %c"
				" %c%s %s"
				"%s",
				ii.ttl, ii.id_str, ii.frag,
				ii.dir, ii.raddr_str, ti.errstr,
				ii.an);
		}
	}else if(ii.proto == IPPROTO_UDP){
		struct udpinfo ui;
		if(udp_preformat(&ui, ip, dir)){
			return snprintf(s, len,
				"%u %s %c"
				" :%u%c%s:%u|%u"
				"%s%s",
				ii.ttl, ii.id_str, ii.frag,
				ui.lport, ii.dir, ii.raddr_str, ui.rport, ui.alen,
				ui.an, ii.an);
		}else{
			return snprintf(s, len,
				"%u %s %c"
				" %c%s %s"
				"%s",
				ii.ttl, ii.id_str, ii.frag,
				ii.dir, ii.raddr_str, ui.errstr,
				ii.an);
		}
	}
	return 0;
}
int packet_snprint_human(char *s, size_t len, const void *ip, 
                         const struct timeval *time, int dir, 
                         const void *start_timeval){
	struct ipinfo ii;
	const struct timeval *start = start_timeval;
	struct timeval t;

	t.tv_sec = time->tv_sec - start->tv_sec;
	t.tv_usec = time->tv_usec - start->tv_usec;
	if(t.tv_usec < 0)t.tv_usec += 1000000;

	ip_preformat(&ii, ip, dir);
	if(ii.proto == IPPROTO_TCP){
		struct tcpinfo ti;
		if(tcp_preformat(&ti, ip, dir)){
			return snprintf(s, len,
				"%d.%03d"
				" ttl=%u id=%s frag=%s"
				" %s:%u%c%s:%u"
				" [%s] seq=%u ack=%u win=%u opts=%u (%u)"
				"%s%s",
				(int)t.tv_sec, (int)t.tv_usec/1000,
				ii.ttl, ii.id_str, ii.frag_str,
				ii.laddr_str, ti.lport, ii.dir, ii.raddr_str, ti.rport,
				ti.flags, ti.seq, ti.ack, ti.window, ti.optlen, ti.alen,
				ti.an, ii.an);
		}else{
			return snprintf(s, len,
				"%d.%03d"
				" ttl=%u id=%s frag=%s"
				" %s%c%s %s"
				"%s",
				(int)t.tv_sec, (int)t.tv_usec/1000,
				ii.ttl, ii.id_str, ii.frag_str,
				ii.laddr_str, ii.dir, ii.raddr_str, ti.errstr,
				ii.an);
		}
	}else if(ii.proto == IPPROTO_UDP){
		struct udpinfo ui;
		if(udp_preformat(&ui, ip, dir)){
			return snprintf(s, len,
				"%d.%03d"
				" ttl=%u id=%s frag=%s"
				" %s:%u%c%s:%u (%u)"
				"%s%s",
				(int)t.tv_sec, (int)t.tv_usec/1000,
				ii.ttl, ii.id_str, ii.frag_str,
				ii.laddr_str, ui.lport, ii.dir, ii.raddr_str, ui.rport, ui.alen,
				ui.an, ii.an);
		}else{
			return snprintf(s, len,
				"%d.%03d"
				" ttl=%u id=%s frag=%s"
				" %s%c%s %s"
				"%s",
				(int)t.tv_sec, (int)t.tv_usec/1000,
				ii.ttl, ii.id_str, ii.frag_str,
				ii.laddr_str, ii.dir, ii.raddr_str, ui.errstr,
				ii.an);
		}
	}
	return 0;
}
int packet_snprint_machine(char *s, size_t len, const void *ip, 
                           const struct timeval *time, int dir, const void *_){
	(void)_;
	struct ipinfo ii;
	ip_preformat(&ii, ip, dir);
	if(ii.proto == IPPROTO_TCP){
		struct tcpinfo ti;
		if(tcp_preformat(&ti, ip, dir)){
			return snprintf(s, len,
				"%d.%06d"
				" %u %u %c %u %u"
				" %u %u %s %u %u %u %u %u"
				"%s%s",
				(int)time->tv_sec, (int)time->tv_usec,
				ii.ttl, ii.id, ii.frag, ii.saddr, ii.daddr,
				ti.lport, ti.rport, 
				ti.flags, ti.seq, ti.ack, ti.window, ti.optlen, ti.alen,
				ti.an, ii.an);
		}else{
			return snprintf(s, len,
				"%d.%06d"
				" %u %u %c %u %u"
				" %s"
				"%s",
				(int)time->tv_sec, (int)time->tv_usec,
				ii.ttl, ii.id, ii.frag, ii.saddr, ii.daddr,
				ti.errstr,
				ii.an);
		}
	}else if(ii.proto == IPPROTO_UDP){
		struct udpinfo ui;
		if(udp_preformat(&ui, ip, dir)){
			return snprintf(s, len,
				"%d.%06d"
				" %u %u %c %u %u"
				" %u %u %u"
				"%s%s",
				(int)time->tv_sec, (int)time->tv_usec,
				ii.ttl, ii.id, ii.frag, ii.saddr, ii.daddr,
				ui.lport, ui.rport, ui.alen,
				ui.an, ii.an);
		}else{
			return snprintf(s, len,
				"%d.%06d"
				" %u %u %c %u %u"
				" %s"
				"%s",
				(int)time->tv_sec, (int)time->tv_usec,
				ii.ttl, ii.id, ii.frag, ii.saddr, ii.daddr,
				ui.errstr,
				ii.an);
		}
	}
	return 0;
}
