#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

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
int do_checksum(char* buf, int proto, int len){
	struct ip* iph = (struct ip*)buf;
	int sum = 0;
	int ip_hl = iph->ip_hl << 2;

	if (len == 0)
		return -1;

	switch (proto){
		case IPPROTO_TCP: {
			struct tcphdr *tcph =	(struct tcphdr *)(buf + ip_hl);
			tcph->th_sum = 0;
			sum = in_cksum((u_int16_t *)&iph->ip_src, 8);
			sum += ntohs(IPPROTO_TCP + len);
			sum += in_cksum((u_int16_t *)tcph, len);
			tcph->th_sum = CKSUM_CARRY(sum);
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph =	(struct udphdr *)(buf + ip_hl);
			udph->uh_sum = 0;
			sum = in_cksum((u_int16_t *)&iph->ip_src, 8);
			sum += ntohs(IPPROTO_UDP + len);
			sum += in_cksum((u_int16_t *)udph, len);
			udph->uh_sum = CKSUM_CARRY(sum);
			break;
		}
		case IPPROTO_ICMP: {
			struct icmphdr *icmph =	(struct icmphdr *)(buf + ip_hl);
			icmph->checksum = 0;
			sum += in_cksum((u_int16_t *)icmph, len);
			icmph->checksum = CKSUM_CARRY(sum);
			break;
		}
		case IPPROTO_IGMP: {
			struct igmp *igmph = (struct igmp *)(buf + ip_hl);
			igmph->igmp_cksum = 0;
			sum = in_cksum((u_int16_t *)igmph, len);
			igmph->igmp_cksum = CKSUM_CARRY(sum);
			break;
		}
	}
	return 0;
}
