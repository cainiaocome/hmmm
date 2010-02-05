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

static int itoa(char *s, unsigned int i){
	int len = (i < 10 ? 1 : i < 100 ? 2 : i < 1000 ? 3 : \
i < 10000 ? 4 : i < 100000 ? 5 : i < 1000000 ? 6 : \
i < 10000000 ? 7 : i < 100000000 ? 8 : i < 1000000000 ? 9 : 10);
	s += len;
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
	if(*--s=(char)('0'+i%10), i/=10)
		*--s=(char)('0'+i);
	return len;
}
static int ntoa(char *s, int addr){
	unsigned char *a = (unsigned char *)&addr;
	char *t = s;
	t += itoa(t, a[0]);
	*t++ = '.';
	t += itoa(t, a[1]);
	*t++ = '.';
	t += itoa(t, a[2]);
	*t++ = '.';
	t += itoa(t, a[3]);
	return t - s;
}

#define intcpy(dest, src) (*(int*)(dest) = *(int*)(src), 4)
#define ip_ttl(s, ip) itoa(s, ip->ttl)
#define ip_id(s, ip, dir) ((dir && !ip->id) ? intcpy(s, "auto") : itoa(s, ntohs(ip->id)))
#define ip_frag(s, ip) \
((*(char*)s = !(off & 0xe000) ? '/' \
	: (off & IP_DF) ? 'D' \
	: (off & IP_MF) ? 'M' : 'V'), 1)
#define ip_frag_str(s, ip) (!ip->frag_off ? 0 \
	: intcpy(s, (off & IP_DF ? "dont" \
		: off & IP_MF ? "more" : "rsvr")))



#define tcp_valid(tlen) ((size_t)tlen >= sizeof(struct tcphdr))
#define tcp_lport(s, tcp, dir) itoa(s, ntohs(dir?tcp->source:tcp->dest))
#define tcp_rport(s, tcp, dir) itoa(s, ntohs(dir?tcp->dest:tcp->source))
#define tcp_seq(s, tcp) itoa(s, ntohl(tcp->seq))
#define tcp_ack(s, tcp) itoa(s, ntohl(tcp->ack_seq))
#define tcp_window(s, tcp) itoa(s, ntohs(tcp->window))
#define tcp_optlen(s, tcp) itoa(s, (tcp->doff << 2) - sizeof(struct tcphdr))
static inline int tcp_flags(char *s, const struct tcphdr *tcp){
	char *t = s;
	if(tcp->fin)*t++='F';
	if(tcp->syn)*t++='S';
	if(tcp->rst)*t++='R';
	if(tcp->psh)*t++='P';
	if(tcp->ack)*t++='A';
	if(tcp->urg)*t++='U';
	if(tcp->res2 & 1)*t++='E';
	if(tcp->res2 & 2)*t++='C';
	if(t == s)*t++='_';
	return t - s;
}
#define tcp_alen(s, tcp, tlen) itoa(s, tlen - (tcp->doff << 2))


#define udp_valid(tlen) ((size_t)tlen >= sizeof(struct udphdr))
#define udp_lport(s, udp, dir) itoa(s, ntohs(dir?udp->source:udp->dest))
#define udp_rport(s, udp, dir) itoa(s, ntohs(dir?udp->dest:udp->source))
#define udp_alen(s, tlen) itoa(s, tlen - sizeof(struct udphdr))

int packet_sprint_short_fast(char *s, const void *buf, 
                             const struct timeval *time, int dir){
	char *t = s;
	const struct iphdr *ip = buf;
	int off = ntohs(ip->frag_off);
	int tlen = ntohs(ip->tot_len) - (ip->ihl << 2);

	/* time */
	t += itoa(t, time->tv_sec);
	t += intcpy(t, ".000");
	t += intcpy(t, "000 ");
	t -= (time->tv_usec < 10 ? 1 
		: time->tv_usec < 100 ? 2 
		: time->tv_usec < 1000 ? 3 
		: time->tv_usec < 10000 ? 4 
		: time->tv_usec < 100000 ? 5 
		: 6) + 1;
	t += itoa(t, time->tv_usec) + 1;

	/* ttl id frag */
	t += ip_ttl(t, ip);
	*t++ = ' ';
	t += ip_id(t, ip, dir);
	*t++ = ' ';
	t += ip_frag(t, ip);

	if(ip->protocol == IPPROTO_TCP){
		const struct tcphdr *tcp = buf + (ip->ihl << 2);
		if(tcp_valid(tlen)){
			/* :lport dir raddr:rport flags seq:ack window|alen */
			t += (intcpy(t, " :__"), 2);
			t += tcp_lport(t, tcp, dir);
			*t++ = (dir ? '>' : '<');
			t += ntoa(t, dir?ip->daddr:ip->saddr);
			*t++ = ':';
			t += tcp_rport(t, tcp, dir);
			*t++ = ' ';
			t += tcp_flags(t, tcp);
			*t++ = ' ';
			t += tcp_seq(t, tcp);
			*t++ = ':';
			t += tcp_ack(t, tcp);
			*t++ = ' ';
			t += tcp_window(t, tcp);
			*t++ = '|';
			t += tcp_alen(t, tcp, tlen);
		}else{
			/* dir raddr */
			*t++ = ' ';
			*t++ = (dir ? '>' : '<');
			t += ntoa(t, dir?ip->daddr:ip->saddr);
		}

		/* tcp anomalies */
		if((size_t)tlen < sizeof(struct tcphdr)){
			*t++ = ' ';
			t += intcpy(t, "tcp=");
			t += itoa(t, tlen);
		}else if((size_t)(tcp->doff << 2) < sizeof(struct tcphdr)){
			*t++ = ' ';
			t += intcpy(t, "dof=");
			t += itoa(t, tcp->doff << 2);
		}else{
			if(tcp->res1){
				*t++ = ' ';
				t += intcpy(t, "res=");
				t += itoa(t, tcp->res1);
			}
			if(tcp->urg_ptr){
				*t++ = ' ';
				t += intcpy(t, "urg=");
				t += itoa(t, ntohs(tcp->urg_ptr));
			}
			if(!dir && tcp->check != tcp_cksum(ip, tlen)){
				t += intcpy(t, " cke");
				t += intcpy(t, "rr=1");
			}
			if(gfw_fingerprint(ip)){
				*t++ = ' '; 
				t += intcpy(t, "gfw=");
				t += gfw_fingerprint_sprint(t, ip);
			}
		}
	}else if(ip->protocol == IPPROTO_UDP){
		const struct udphdr *udp = buf + (ip->ihl << 2);
		if(udp_valid(tlen)){
			/* :lport dir raddr rport|alen */
			t += (intcpy(t, " :__"), 2);
			t += udp_lport(t, udp, dir);
			*t++ = (dir ? '>' : '<');
			t += ntoa(t, dir?ip->daddr:ip->saddr);
			*t++ = ':';
			t += udp_rport(t, udp, dir);
			*t++ = '|';
			t += udp_alen(t, tlen);
		}else{
			/* dir raddr */
			*t++ = ' ';
			*t++ = (dir ? '>' : '<');
			t += ntoa(t, dir?ip->daddr:ip->saddr);
		}

		/* udp anomalies */
		if((size_t)tlen < sizeof(struct udphdr)){
			*t++ = ' ';
			t += intcpy(t, "udp=");
			*t++ = (char)('0' + tlen%10);
		}else{
			if(tlen != ntohs(udp->len)){
				t += intcpy(t, " lne");
				t += intcpy(t, "rr=1");
			}
			if(!dir && udp->check != udp_cksum(ip, tlen)){
				t += intcpy(t, " cke");
				t += intcpy(t, "rr=1");
			}
			if(gfw_fingerprint(ip)){
				*t++ = ' '; 
				t += intcpy(t, "gfw=");
				t += gfw_fingerprint_sprint(t, ip);
			}
		}
	}

	/* ip anomalies */
	if((unsigned)(ip->ihl << 2) > sizeof(struct iphdr)){
		*t++ = ' ';
		t += intcpy(t, "ipo=");
		t += itoa(t, (ip->ihl << 2) - sizeof(struct iphdr));
	}
	if(ip->tos){
		*t++ = ' ';
		t += intcpy(t, "tos=");
		t += itoa(t, ip->tos);
	}

	if(off & IP_MF){
		t += intcpy(t, " fra");
		t += intcpy(t, "g=M+");
		t += itoa(t, (off & IP_OFFMASK) << 3);
	}else if(off & IP_OFFMASK){
		t += intcpy(t, " fra");
		t += intcpy(t, "g=?+");
		t[-2] = !(off & 0xe000) ? '/' : off & IP_DF ? 'D' : 'V';
		t += itoa(t, (off & IP_OFFMASK) << 3);
	}else if(off & IP_RF){
		t += intcpy(t, " fra");
		t += (intcpy(t, "g=V "), 3);
	}
	return t - s;
}



