#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "log.h"

#define IPV4_H 20
#define TCP_H 20
#define UDP_H 8

#include "net.h"
#include "packet.h"
#include "cksum.h"

extern packet* packets_tail;
extern packet* packets_head;
extern int send_delay;

long long bandwidth = 0;//-b
double net_timeout = 5.;
int mtu;
int ttl = 255;//-T
int udp_mode = 0;//-u

struct in_addr local_addr = {0};
u_short local_port;//-p
struct in_addr dst_addr = {0};
int dst_net;
u_short dst_port;

tcp_seq seq, ack, isn, ian;
u_short ip_id;

static int ian_seen = 0;

static int sock = 0;

static struct timeval lastcomm = {0x7fffffffL, 999999};
#define ELAPS(a,b) ((a.tv_sec-b.tv_sec)*1e6+a.tv_usec-b.tv_usec)

#if __linux__
#  define IP_MTU 14
static int get_mtu(){
	if(!sock)
		return -1;
	int mtu;
	socklen_t len = sizeof(mtu);
	TRY( getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &len) );
	return mtu;
}
#elif (__MINGW32__)
/* ... */
#endif

void net_init(){
	if(sock){
		DEBUG("socket not initialized.");
		return;
	}

	/*XXX CAP_NET_RAW  */
	TRY( sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW) );
	DEBUG("sock set up.");

	socklen_t optlen;

	/* no linger */
	struct linger lg = { 0, 0 };
	TRY( setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) );

	/* high socket priority
	XXX CAP_NET_ADMIN 
	*/
	int sockpri = 1000;
	TRY( setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &sockpri, sizeof(sockpri)) );

	/* recv timestamp */
	int on = 1;
	TRY( setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) );

	/* set recv timeout */
	struct timeval rto = {0, 1};
	TRY( setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto)) );

	/* given local_addr, try to bind */
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = IPPROTO_RAW;
	local.sin_addr = local_addr;
	if(!local_addr.s_addr 
		&& bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0){
		if(errno == EADDRNOTAVAIL){
			INFO("Non-local source addr: %s", inet_ntoa(local_addr));
			local.sin_addr.s_addr = INADDR_ANY;
			TRY( bind(sock, (struct sockaddr*)&local, sizeof(local)) );
		}else{
			ERROR("bind");
		}
	}

	/* autobind */
	struct sockaddr_in dst;
	dst.sin_family = AF_INET;
	dst.sin_port = IPPROTO_RAW;
	dst.sin_addr = dst_addr;
	TRY( connect(sock, (struct sockaddr*)&dst, sizeof(dst)) );
	DEBUG("sock connected.");

	/* get mtu */
	mtu = get_mtu();
	DEBUG("mtu is %d.", mtu);

	/* if local addr not given, fill in it with autobind result */
	optlen = sizeof(local);
	TRY( getsockname(sock, (struct sockaddr*)&local, &optlen) );
	if(!local_addr.s_addr)
		local_addr = local.sin_addr;
	INFO("bind addr: %s", inet_ntoa(local_addr));

	isn = rand();
	seq = isn;
	ian = rand();
	ack = ian + 1;
	ip_id = rand()%65535 + 1;
}

void net_read(){
	if(!sock){
		DEBUG("socket not initialized.");
		return;
	}

	char buf[IP_MAXPACKET];
	struct ip* iph = (struct ip*)buf;
	char ctlbuf[4096];
	struct timeval* recv_time = NULL;
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg = {NULL, 0, &iov, 1, ctlbuf, sizeof(ctlbuf), 0};
	ssize_t recv_s;

	if((recv_s = recvmsg(sock, &msg, MSG_DONTWAIT)) < 0){
		if(errno == EAGAIN){
			struct timeval now;
			gettimeofday(&now, NULL);
			if(net_timeout > 0 && ELAPS(now, lastcomm)/1e6 > net_timeout){
				MESSAGE("net read timed out");
				exit(EXIT_SUCCESS);
			}else
				return;
		}else
			ERROR("recvmsg");
	}

	/* get timestamp */	
	struct cmsghdr* cmsg;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; 
	cmsg = CMSG_NXTHDR(&msg,cmsg)){
		if(cmsg->cmsg_level == SOL_SOCKET
		&& cmsg->cmsg_type == SO_TIMESTAMP
		&& cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timeval))){
			recv_time = (struct timeval*)CMSG_DATA(cmsg);
			break;
		}
	}

	/* filter */
	u_short* sport = (u_short*)(buf + iph->ip_hl*4);
	u_short* dport = (u_short*)(buf + iph->ip_hl*4 + 2);
	if(recv_s < IPV4_H+2 || iph->ip_v != IPVERSION
	|| (iph->ip_p != IPPROTO_TCP && iph->ip_p != IPPROTO_UDP)
	|| recv_s - iph->ip_hl*4 < 2
	|| iph->ip_dst.s_addr != local_addr.s_addr
	|| iph->ip_src.s_addr != dst_addr.s_addr
	|| *sport != dst_port || *dport != local_port)
		return;

	DEBUG("new datagram.");

	lastcomm = *recv_time;

	/* new packet */
	packets_tail = packet_new(buf, recv_s, recv_time, packets_tail);
	if(packets_head == NULL)
		packets_head = packets_tail;
	if(iph->ip_p == IPPROTO_TCP){
		if(!ian_seen && ntohl(packets_tail->tcp->th_ack)){
			ian = ntohl(packets_tail->tcp->th_seq);
			ack = ian + 1;
		}
		ack = ntohl(packets_tail->tcp->th_seq);
	}
	packet_print(packets_tail);
}

void net_send(int _ttl, int f, u_long s, u_long a, char* p, size_t ps){
	if(!sock){
		DEBUG("socket not initialized.");
		return;
	}
	DEBUG("%d,%d,%lu,%lu,%s,%u",_ttl,f,s,a,p,ps);
	static size_t lastbyte = 0;
	static struct timeval lastsent = {0, 0};
	if(!ps)p = NULL;
	if(p == NULL)ps = 0;
	size_t sentbyte = 0;

	/* construct packet */
	char buf[IP_MAXPACKET] = {0};
	struct ip* iph = (struct ip*)buf;
	iph->ip_hl = IPV4_H >> 2;
	iph->ip_v = IPVERSION;
	iph->ip_tos = 0;
	iph->ip_len = htons(IPV4_H + (udp_mode ? UDP_H : TCP_H) + ps);
	iph->ip_id = ip_id;
	iph->ip_off = 0;
	iph->ip_ttl = _ttl;
	iph->ip_p = udp_mode ? IPPROTO_UDP : IPPROTO_TCP;
	iph->ip_src = local_addr;
	DEBUG("local_addr: %s", inet_ntoa(local_addr));
	iph->ip_dst = dst_addr;
	sentbyte += IPV4_H;
	ip_id = ip_id+1 ?: 1;
	if(!udp_mode){
		struct tcphdr* tcph = (struct tcphdr*)(buf + IPV4_H);
		tcph->th_sport = htons(local_port);
		tcph->th_dport = htons(dst_port);
		tcph->th_seq = htonl(s);
		tcph->th_ack = htonl(a);
		tcph->th_x2 = 0;
		tcph->th_off = TCP_H >> 2;
		tcph->th_flags = f;
		tcph->th_win = 0xffff;
		tcph->th_urp = 0;
		if(p != NULL)
			memcpy(buf + IPV4_H + TCP_H, p, ps);
		do_checksum(buf, IPPROTO_TCP, TCP_H + ps);

		if(f == TH_SYN)
			seq++;
		/*XXX syn with payload causes target-based difference */
		seq += ps;
		sentbyte += TCP_H + ps;
	}else{
		struct udphdr* udph = (struct udphdr*)(buf + IPV4_H);
		udph->uh_sport = htons(local_port);
		udph->uh_dport = htons(dst_port);
		udph->uh_ulen = htons(UDP_H + ps);
		if(p != NULL)
			memcpy(buf + IPV4_H + UDP_H, p, ps);
		do_checksum(buf, IPPROTO_UDP, UDP_H + ps);

		sentbyte += UDP_H + ps;
	}

	/* wait the delay */
	DEBUG("usleep: %d", send_delay);
	usleep(send_delay);
	send_delay = 0;

	/* keep bitrate limit */
	if(bandwidth){
		struct timeval now;
		gettimeofday(&now, NULL);
		double bitrate_delay = lastbyte*8e6/bandwidth - ELAPS(now, lastsent);
		if(bitrate_delay >= 1){
			DEBUG("bandwidth throttling usleep: %.0f", bitrate_delay);
			usleep(bitrate_delay);
		}
	}

	packets_tail = packet_new(buf, sentbyte, NULL, packets_tail);
	if(packets_head == NULL)
		packets_head = packets_tail;

	//send...
	TRY( (signed)(send(sock, buf, sentbyte, 0) - sentbyte) );

	/* clean up */
	gettimeofday(&lastsent, NULL);
	lastbyte = sentbyte;
	lastcomm = lastsent;
	packets_tail->time = lastsent;
	packet_print(packets_tail);
}

void net_cleanup(){
	if(!sock){
		DEBUG("socket not initialized.");
		return;
	}
	close(sock);
	DEBUG("socket closed.");
}