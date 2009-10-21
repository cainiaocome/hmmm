#include "net_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "packet.h"
#include "log.h"

#define IPV4_H 20
#define TCP_H 20
#define UDP_H 8

extern tcp_seq isn, ian;
extern struct in_addr dst_addr;
extern struct timeval init_time;

int print_ascii = 0;//-A
int print_payload = 0;//-P
int print_hex = 0;//-x
int print_analysis = 0;//-a

#define PRINT(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#define PUT(c) fputc(c, stderr)

static void printhex(char* s, size_t n){
	size_t i;
	for(i = 0; i < n; i++)
#if __linux__
		PRINT("%02hhx", s[i]);
#elif __MINGW32__
		PRINT("%02x", s[i]);
#endif
}
/*

*/
packet* packet_new(void* p, size_t len, struct timeval* t){
	struct ip* iph = p;
	packet* pkt = malloc(sizeof(packet));
	if(pkt == NULL)
		return NULL;
	memset(pkt, 0, sizeof(packet));

#define WRONGSIZE(s) {s = UFW_INVALID_SIZE;goto packet_parse_end;}
#define SMALLSIZE(s) {s = UFW_SMALL_SIZE;goto packet_parse_end;}
	pkt->len = ntohs(iph->ip_len);
	if(pkt->len < len)
		SMALLSIZE(pkt->len)
	else if(pkt->len > len)
		WRONGSIZE(pkt->len)
	else if(pkt->len < IPV4_H)
		SMALLSIZE(pkt->iph_len)

	pkt->iph_len = iph->ip_hl << 2;
	if(pkt->iph_len < IPV4_H)
		WRONGSIZE(pkt->iph_len);
	if(pkt->iph_len > pkt->len)
		WRONGSIZE(pkt->iph_len);

	pkt->hdr = memcpy(malloc(len), p, len);
	pkt->ipopts_s = pkt->iph_len - IPV4_H;
	if(pkt->ipopts_s)
		pkt->ipopts = (char*)pkt->hdr + IPV4_H;
	pkt->proto = pkt->hdr->ip_p;
	switch(pkt->proto){
		case IPPROTO_TCP:
			if(len - pkt->iph_len < TCP_H)
				SMALLSIZE(pkt->tcph_len);
			pkt->tcp = (void*)((char*)pkt->hdr + pkt->iph_len);
			pkt->tcph_len = pkt->tcp->th_off*4;
			pkt->tcp = NULL;
			if(pkt->tcph_len < TCP_H) //smaller than minimal header
				WRONGSIZE(pkt->tcph_len);
			pkt->tcp = (void*)((char*)pkt->hdr + pkt->iph_len);
			pkt->tcpopts_s = pkt->tcph_len - TCP_H;
			if(pkt->tcpopts_s)
				pkt->tcpopts = (char*)pkt->tcp + TCP_H;
			if(pkt->tcph_len > len - pkt->iph_len) //larger than ip payload
				SMALLSIZE(pkt->appdata_s);
			pkt->appdata_s = len - pkt->iph_len - pkt->tcph_len;
			if(pkt->appdata_s)
				pkt->appdata = (char*)pkt->tcp + pkt->tcph_len;
			break;
		case IPPROTO_UDP:
			if(len - pkt->iph_len < UDP_H)
				SMALLSIZE(pkt->udph_len);
			pkt->udph_len = UDP_H;
			pkt->udp = (void*)((char*)pkt->hdr + pkt->iph_len);
			if(ntohs(pkt->udp->uh_ulen) > len - pkt->iph_len)//larger than ip paylaod
				SMALLSIZE(pkt->appdata_s);
			pkt->appdata_s = len - pkt->iph_len - UDP_H;
			if(pkt->appdata_s)
				pkt->appdata = (char*)pkt->udp + UDP_H;
			if(ntohs(pkt->udp->uh_ulen) < UDP_H) //smaller than minimal header
				WRONGSIZE(pkt->appdata_s);
			break;
		default:
			//not supported;
			break;
	}

packet_parse_end:
	if(t != NULL)
		pkt->time = *t;
	return pkt;
}

void packet_free(void* i){
	packet* p = i;
	if(p->hdr != NULL)
		free(p->hdr);
	free(p);
}

static void appdata_print(char* p, size_t n){
	size_t i;
	for(i = 0; i < n && print_payload; i++){
		if(isprint(p[i]))
			PUT(p[i]);
		else if(print_ascii)
			PUT('.');
		else if(print_hex)
#if __linux__
			PRINT("\\x%02hhx", p[i]);
#elif __MINGW32__
			PRINT("\\x%02x", p[i]);
#endif
		else
			PUT(p[i]);
	}
	if(print_payload && n)
		PRINT("-- APPDATA EOF\n");
}
static void tcp_packet_print(packet* p){
	if(p->proto != IPPROTO_TCP)
		return;
	struct tcphdr* t = p->tcp;
	tcp_seq _isn = isn, _ian = ian;
	if(p->hdr->ip_src.s_addr == dst_addr.s_addr){//inbound
		_isn = ian;
		_ian = isn;
	}
#ifdef _PACKET_FULLADDR
	PRINT("%5u>%-5u %d:", ntohs(t->th_sport), ntohs(t->th_dport), 
					ntohl(t->th_seq) - _isn);
	PRINT(t->th_ack?"%d ":"* ", ntohl(t->th_ack) - _ian);
	PRINT("%u ", ntohs(t->th_win));
#else
	PRINT(" %10u:", (u_int)(ntohl(t->th_seq) - _isn));
	PRINT(t->th_ack?"%-10u ":"*          ", (u_int)(ntohl(t->th_ack) - _ian));
	PRINT("%5u ", ntohs(t->th_win));
#endif
	if(t->th_flags & TH_FIN)PUT('F');
	if(t->th_flags & TH_SYN)PUT('S');
	if(t->th_flags & TH_RST)PUT('R');
	if(t->th_flags & TH_PUSH)PUT('P');
	if(t->th_flags & TH_ACK)PUT('A');
	if(t->th_flags & TH_URG)PUT('U');
	if(t->th_flags & TH_ECE)PUT('E');
	if(t->th_flags & TH_CWR)PUT('C');
	if(t->th_flags == 0)PUT('_');
	if(t->th_x2)PRINT(" x2:%1x", t->th_x2);

	if(p->tcpopts_s > 0)
		PUT(' ');
	size_t i;
	for(i = 0; i < p->tcpopts_s;){
			char buf[50];
			buf[0] = 0;
			char kind = p->tcpopts[i];
			switch(kind){
				case TCPOPT_EOL:
					PUT('.');
					break;
				case TCPOPT_NOP:
					PUT('_');
					break;
				case TCPOPT_MAXSEG:
					PRINT("MSS=%04x;", ntohs(*(u_short*)&p->tcpopts[i+2]));
					break;
				case TCPOPT_WINDOW:
					PRINT("WS=%02x;", p->tcpopts[i+2]);
					break;
				case TCPOPT_SACK_PERMITTED:
					PRINT("SAP;");
					break;
				case TCPOPT_SACK:
					PRINT("SACK");
					printhex(&p->tcpopts[i+2], p->tcpopts[i+1]-2);
					PUT(';');
					break;
				case TCPOPT_TIMESTAMP:
					PRINT("TS=%08x:%08x;", (u_int)ntohl(*(u_int*)&p->tcpopts[i+2]), 
							(u_int)ntohl(*(u_int*)&p->tcpopts[i+6]));
					break;
				default:
					PRINT("%02x=", kind);
					printhex(&p->tcpopts[i+2], p->tcpopts[i+1]-2);
					PUT(';');
			}
			i += kind > 1 ? (u_int)p->tcpopts[i+1] : 1;
	}
	if(print_analysis){
		if(ntohs(t->th_win) % 17 == 0 
		&& ntohs(p->hdr->ip_id) == 64
		&& !(ntohs(p->hdr->ip_off) & IP_DF))
			PRINT(" TYPE-I");
		if(ntohs(p->hdr->ip_id) == (u_short)(-1 - ntohs(t->th_win)*13)
		&& (ntohs(p->hdr->ip_off) & IP_DF))
			PRINT(" TYPE-II");
	}
	if(p->appdata_s == UFW_SMALL_SIZE){
		PRINT(" [INVALID PAYLOAD LENGTH]\n");
		return;
	}
	if(p->appdata_s)
		PRINT(" (%u)", p->appdata_s);
	PUT('\n');

	appdata_print(p->appdata, p->appdata_s);
}

static void udp_packet_print(packet* p){
#ifdef _PACKET_FULLADDR
	struct udphdr* u = p->udp;
	PRINT("%5u>%-5u", ntohs(u->uh_sport), ntohs(u->uh_dport));
#endif
	if(p->appdata_s == UFW_SMALL_SIZE){
		p->appdata_s = p->len - p->iph_len - p->udph_len;
		PRINT(" [INVALID PAYLOAD LENGTH: %d]", p->appdata_s);
	}
	if(p->appdata_s)
		PRINT(" (%u)", p->appdata_s);
	PUT('\n');

	appdata_print(p->appdata, p->appdata_s);
}

void packet_print(packet* p){
	PRINT("%.6f ", p->time.tv_sec - init_time.tv_sec
		+ (p->time.tv_usec - init_time.tv_usec)/1e6);
	if(p->len == UFW_INVALID_SIZE){
		PRINT("[IP PACKET SIZE MORE THAN RECEIVED]\n");
		return;
	}
	if(p->len == UFW_SMALL_SIZE){
		PRINT("[IP PACKET SIZE LESS THAN RECEIVED]\n");
		return;
	}
	if(p->iph_len == UFW_INVALID_SIZE){
		PRINT("[IP HEADER LENGTH INVALID]\n");
		return;
	}
	if(p->iph_len == UFW_SMALL_SIZE){
		PRINT("[IP HEADER LENGTH INSUFFICIENT]\n");
		return;
	}
	struct ip* h = p->hdr;
	if(h->ip_tos){
		PRINT("tos:");
		if(h->ip_tos & IPTOS_LOWDELAY)PUT('D');
		if(h->ip_tos & IPTOS_THROUGHPUT)PUT('T');
		if(h->ip_tos & IPTOS_RELIABILITY)PUT('R');
		if(h->ip_tos & IPTOS_LOWCOST)PUT('C');

		if(h->ip_tos & IPTOS_PREC_NETCONTROL)PUT('n');
		if(h->ip_tos & IPTOS_PREC_INTERNETCONTROL)PUT('I');
		if(h->ip_tos & IPTOS_PREC_CRITIC_ECP)PUT('c');
		if(h->ip_tos & IPTOS_PREC_FLASHOVERRIDE)PUT('F');
		if(h->ip_tos & IPTOS_PREC_FLASH)PUT('f');
		if(h->ip_tos & IPTOS_PREC_IMMEDIATE)PUT('i');
		if(h->ip_tos & IPTOS_PREC_PRIORITY)PUT('p');
		if(h->ip_tos & IPTOS_PREC_ROUTINE)PUT('r');
		PUT(' ');
	}

	PRINT("%5u ", ntohs(h->ip_id));
	u_int t = ntohs(h->ip_off);
	PRINT("%c%c%c ", IP_RF&t?'R':'_', IP_DF & t?'D':'_', IP_MF & t?'M':'_');
	if(IP_OFFMASK & t)PRINT("off:%04x ", IP_OFFMASK & t);
	PRINT("%3u ", h->ip_ttl);
#ifdef _PACKET_FULLADDR
	PRINT("%15s>", inet_ntoa(h->ip_src));
	PRINT("%-15s", inet_ntoa(h->ip_dst));
#else
	if(h->ip_dst.s_addr == dst_addr.s_addr)
		PRINT(">>S");
	else
		PRINT("C<<");
#endif
	if(p->ipopts_s){
		PRINT(" [%d]", p->ipopts_s);
		printhex(p->ipopts, p->ipopts_s);
	}
#ifdef _PACKET_FULLADDR
	PUT('|');
#endif
	switch(p->proto){
		case IPPROTO_TCP:
			if(p->tcph_len == UFW_INVALID_SIZE){
				PRINT("[TCP HEADER LENGTH INVALID]\n");
				return;
			}
			if(p->tcph_len == UFW_SMALL_SIZE){
				PRINT("[TCP HEADER LENGTH INSUFFICIENT]\n");
				return;
			}
			tcp_packet_print(p);
			break;
		case IPPROTO_UDP:
			if(p->udph_len == UFW_SMALL_SIZE){
				PRINT("[UDP HEADER LENGTH INSUFFICIENT]\n");
				return;
			}
			udp_packet_print(p);
			break;
		default://not supported
			PRINT("payload:(%d)\n", p->len - p->iph_len);
			break;
	}
}

