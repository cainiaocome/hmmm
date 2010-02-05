#include "net_config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>

#include <glib.h>

#include "log.h"
#include "net.h"
#include "packet.h"
#include "cksum.h"


#define TRY(s) if((s) < 0){\
	fprintf(stderr, "ufw %s:%d: %s\n", __FILE__, __LINE__, strerror(errno));\
	return -1;}else{}



extern GAsyncQueue* packets;
extern int listen_only;

long long bandwidth = 0;//-b
double net_timeout = -1;
int mtu;
int ttl = 255;//-T
int udp_mode = 0;//-u
size_t received_packets = 0;
struct timeval lastcomm = {0x7fffffffL, 999999};

struct in_addr local_addr;
u_short local_port;//-p
struct in_addr dst_addr;
int dst_net;
u_short dst_port;

tcp_seq seq, ack, isn, ian;
u_short ip_id;
struct timeval init_time;

static int ian_seen = 0;
static int isn_seen = 0;
static int proto;

static int sock = 0;
static GThread* read_thrd;
static int read_exiting = 0;

#define ELAPS(a,b) ((a.tv_sec-b.tv_sec)*1e6+a.tv_usec-b.tv_usec)


void* net_read(void* _){
	(void)_;
	if(!sock){
		DEBUG("socket not initialized.");
		return _;
	}

	char buf[IP_MAXPACKET];
	struct ip* iph = (struct ip*)buf;
	struct timeval recv_time;
	char ctlbuf[4096];
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg = {NULL, 0, &iov, 1, ctlbuf, sizeof(ctlbuf), 0};
	ssize_t recv_s;

for(;!read_exiting;usleep(1)){
	if((recv_s = recvmsg(sock, &msg, 0)) < 0){
		if(errno == EAGAIN){
			struct timeval now;
			gettimeofday(&now, NULL);
			if(net_timeout > 0 && ELAPS(now, lastcomm)/1e6 > net_timeout){
				MESSAGE("net read timed out");
				kill(getpid(), SIGTERM);//should be right
				return _;
			}else
				continue;
		}else{
			ERROR("recvmsg");
			kill(getpid(), SIGTERM);//should be right
			return _;
		}
	}

	/* get timestamp */	
	struct cmsghdr* cmsg;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; 
	cmsg = CMSG_NXTHDR(&msg,cmsg)){
		if(cmsg->cmsg_level == SOL_SOCKET
		&& cmsg->cmsg_type == SO_TIMESTAMP
		&& cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timeval))){
			recv_time = *(struct timeval*)CMSG_DATA(cmsg);
			break;
		}
	}

	/* filter */
	u_short* sport = (u_short*)(buf + iph->ip_hl*4);
	u_short* dport = (u_short*)(buf + iph->ip_hl*4 + 2);
	if(recv_s < IPV4_H+2 || iph->ip_v != IPVERSION
	|| iph->ip_p != proto || recv_s - iph->ip_hl*4 < 2
	|| iph->ip_dst.s_addr != local_addr.s_addr
	|| iph->ip_src.s_addr != dst_addr.s_addr
	|| ntohs(*sport) != dst_port || ntohs(*dport) != local_port)
		continue;

	DEBUG("new datagram.");

	lastcomm = recv_time;

	/* new packet */
	packet* p = packet_new(buf, recv_s, &recv_time);
	if(proto == IPPROTO_TCP && p->tcp != NULL){
		if(listen_only){
			if(!isn_seen){
				isn = ntohl(p->tcp->th_seq);
				isn_seen = 1;
			}
			if(!ian_seen && ntohl(p->tcp->th_ack)){
				ian = ntohl(p->tcp->th_ack) - 1;
				ian_seen = 1;
			}
		}else if(!ian_seen){
			ian = ntohl(p->tcp->th_seq);
			ian_seen = 1;
			ack = ian;
			if(p->tcp->th_flags & TH_SYN)
				ack++;
		}
		/*XXX syn with payload causes target-based difference */
		if(p->appdata)
			ack += p->appdata_s;
	}
	g_async_queue_push(packets, p);
	received_packets++;
	if(!init_time.tv_sec)
		init_time = recv_time;
}
	return _;
}

int net_init(){
	if(sock){
		DEBUG("double init");
		return -1;
	}

	proto = udp_mode ? IPPROTO_UDP : IPPROTO_TCP;

	/*XXX CAP_NET_RAW  */
	TRY( sock = socket(PF_INET, SOCK_RAW, proto) );
	socklen_t optlen;

	/* no linger */
	struct linger lg = { 0, 0 };
	TRY( setsockopt(sock, SOL_SOCKET, SO_LINGER, (char*)&lg, sizeof(lg)) );
	int on = 1;

	/* recv timestamp */
	TRY( setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, (char*)&on, sizeof(on)) );

	/* customize ip hdr */
	TRY( setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&on, sizeof(on)) );

	/* given local_addr, try to bind */
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(proto);
	local.sin_addr = local_addr;
	if(!local_addr.s_addr 
		&& bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0){
		if(errno == EADDRNOTAVAIL){
			INFO("Non-local source addr: %s", inet_ntoa(local_addr));
			local.sin_addr.s_addr = INADDR_ANY;
			TRY( bind(sock, (struct sockaddr*)&local, sizeof(local)) );
		}else{
			ERROR("bind");
			return -1;
		}
	}

	/* autobind */
	struct sockaddr_in dst;
	dst.sin_family = AF_INET;
	dst.sin_port = IPPROTO_TCP;
	dst.sin_addr = dst_addr;
	TRY( connect(sock, (struct sockaddr*)&dst, sizeof(dst)) );
	DEBUG("sock connected.");

	/* get mtu */
	optlen = sizeof(mtu);
#define IP_MTU 14
	TRY( getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &optlen) );
	DEBUG("mtu is %d.", mtu);

	/* if local addr not given, fill in it with autobind result */
	optlen = sizeof(local);
	TRY( getsockname(sock, (struct sockaddr*)&local, &optlen) );
	if(!local_addr.s_addr)
		local_addr = local.sin_addr;
	INFO("bind addr: %s", inet_ntoa(local_addr));

	isn = rand();
	seq = isn;
	ip_id = rand()%65535 + 1;

	GError* err;
	read_thrd = g_thread_create(net_read, NULL, 1, &err);
	if(read_thrd == NULL){
		ERR(err->message);
		return -1;
	}
	return 0;
}








int net_send(int _ttl, int f, u_long s, u_long a, char* p, int ps){
	if(!sock){
		DEBUG("socket not initialized.");
		return -1;
	}
	DEBUG("%d,%d,%lu,%lu,%u",_ttl,f,s,a,ps);
	static size_t lastbyte = 0;
	static struct timeval lastsent = {0, 0};
	if(!ps)p = NULL;
	if(p == NULL)ps = 0;
	if(IPV4_H + (udp_mode ? UDP_H : TCP_H) + ps > mtu){
		MESSAGE("packet is larger than mtu, truncated.");
		ps = mtu - IPV4_H - (udp_mode ? UDP_H : TCP_H);
	}
	size_t sentbyte = 0;

	/* construct packet */
	char buf[IP_MAXPACKET] = {0};
	struct ip* iph = (struct ip*)buf;
	iph->ip_hl = IPV4_H >> 2;
	iph->ip_v = IPVERSION;
	iph->ip_tos = 0;
	iph->ip_len = htons(IPV4_H + (udp_mode ? UDP_H : TCP_H) + ps);
	iph->ip_id = htons(ip_id);
	iph->ip_off = 0;
	iph->ip_ttl = _ttl;
	iph->ip_p = udp_mode ? IPPROTO_UDP : IPPROTO_TCP;
	iph->ip_src = local_addr;
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

		if(!isn_seen){
			if(tcph->th_flags & TH_SYN)
				seq++;
			isn_seen = 1;
		}
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

	packet* pkt = packet_new(buf, sentbyte, NULL);

	//send...
	TRY( send(sock, buf, sentbyte, 0) );

	gettimeofday(&lastsent, NULL);
	lastbyte = sentbyte;
	lastcomm = lastsent;
	pkt->time = lastsent;
	if(!init_time.tv_sec)
		init_time = lastsent;

	g_async_queue_push(packets, pkt);
	return 0;
}

void net_cleanup(){
	if(!sock){
		DEBUG("not initialized.");
		return;
	}
	read_exiting = 1;
	if(read_thrd)
		g_thread_join(read_thrd);
	close(sock);
	DEBUG("socket closed.");
}
