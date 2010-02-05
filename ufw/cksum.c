#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define CKSUM_CARRY(x) \
(x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

static int in_cksum(u_int16_t *addr, int len){
	int sum;
#if 0
	u_int16_t last_byte;

	sum = 0;
	last_byte = 0;
#else
	union {
		u_int16_t s;
		u_int8_t b[2];
	}pad;

	sum = 0;
#endif

	while(len > 1){
		sum += *addr++;
		len -= 2;
	}
#if 0
	if(len == 1){
		*(u_int8_t *)&last_byte = *(u_int8_t *)addr;
		sum += last_byte;
#else
	if(len == 1){
		pad.b[0] = *(u_int8_t *)addr;
		pad.b[1] = 0;
		sum += pad.s;
#endif
	}

	return sum;
}

/* modified from libnet_do_checksum() from libnet_checksum.c */
void do_checksum(int proto, void *buf, int len){
	struct iphdr *ip = (struct iphdr *)buf;
	int sum = 0;
	int ip_hl = ip->ihl << 2;

	if (len == 0)
		return;

	switch (proto){
		case IPPROTO_TCP: {
			struct tcphdr *tcp = (struct tcphdr *)(buf + ip_hl);
			tcp->check = 0;
			sum = in_cksum((u_int16_t *)&ip->saddr, 8);
			sum += ntohs(IPPROTO_TCP + len);
			sum += in_cksum((u_int16_t *)tcp, len);
			tcp->check = CKSUM_CARRY(sum);
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr *)(buf + ip_hl);
			udp->check = 0;
			sum = in_cksum((u_int16_t *)&ip->saddr, 8);
			sum += ntohs(IPPROTO_UDP + len);
			sum += in_cksum((u_int16_t *)udp, len);
			udp->check = CKSUM_CARRY(sum);
			break;
		}
		case IPPROTO_ICMP: {
			struct icmphdr *icmp =	(struct icmphdr *)(buf + ip_hl);
			icmp->checksum = 0;
			sum += in_cksum((u_int16_t *)icmp, len);
			icmp->checksum = CKSUM_CARRY(sum);
			break;
		}
	}
}
