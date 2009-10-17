#include "net_config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#if __linux__
#include <pthread.h>
#elif __MIGNW32__
#include <windows.h>
#endif

#include "log.h"
#include "net.h"
#include "packet.h"
#include "cksum.h"


#if __MINGW32__
#	ifdef errno 
#		undef errno
#	endif
#	define errno WSAGetLastError()
#endif

extern packet** packets_buf;
extern size_t packets_limit;
extern size_t packets_cur;
extern int listen_only;

long long bandwidth = 0;//-b
double net_timeout = -1;
int mtu;
int ttl = 255;//-T
int udp_mode = 0;//-u

struct in_addr local_addr;
u_short local_port;//-p
struct in_addr dst_addr;
int dst_net;
u_short dst_port;

tcp_seq seq, ack, isn, ian;
u_short ip_id;

static int ian_seen = 0;
static int isn_seen = 0;
static int proto;

#if __linux__
static int sock = 0;
#elif __MINGW32__
static SOCKET sock = 0;
#endif

#if __linux__
static pthread_t thrd_read;
static pthread_t thrd_print;
static int thread_create(pthread_t* thread, void*(*func)(void*)){
	int r = pthread_create(thread, NULL, func, NULL);
	return r > 0 ? -r : r;
}

#elif __MINGW32__
uintptr_t thrd_read;
uintptr_t thrd_print;
static int thread_create(uintptr_t* thread, unsigned(__stdcall * func)(void*)){
	*thread = _beginthreadex(NULL, 0, func, NULL, 0, NULL);
	return *thread == 0 ? -1 : 0;
}
#endif

static struct timeval lastcomm = {0x7fffffffL, 999999};
#define ELAPS(a,b) ((a.tv_sec-b.tv_sec)*1e6+a.tv_usec-b.tv_usec)

static int get_mtu(){
	if(!sock)
		return -1;
	int mtu = -1;

#if __linux__
#	define IP_MTU 14
	socklen_t len = sizeof(mtu);
	if(getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &len) < 0)
		return -1;

#elif __MINGW32__
	int iter = 0;
	DWORD ret;
	IP_ADAPTER_ADDRESSES* adapters = NULL;
	do {
		ULONG buf_s = 15000;
		adapters = (IP_ADAPTER_ADDRESSES*)malloc(buf_s);
		if (adapters == NULL) {
			return -1;
		}

		ULONG flags = GAA_FLAG_SKIP_ANYCAST	| GAA_FLAG_SKIP_DNS_SERVER
			| GAA_FLAG_SKIP_FRIENDLY_NAME	| GAA_FLAG_SKIP_MULTICAST;
		ret = GetAdaptersAddresses(AF_INET, flags, NULL, adapters, &buf_s);

		if (ret == ERROR_BUFFER_OVERFLOW) {
			free(adapters);
			adapters = NULL;
		} else {
			break;
		}
		iter++;
	} while ((ret == ERROR_BUFFER_OVERFLOW) && (iter < 3));

	if(ret == NO_ERROR){
		IP_ADAPTER_ADDRESSES* cur_adapter = NULL;
		for(cur_adapter = adapters; cur_adapter; cur_adapter = cur_adapter->Next){
			IP_ADAPTER_UNICAST_ADDRESS* uni = NULL;
			for(uni = cur_adapter->FirstUnicastAddress; uni; uni = uni->Next){
				struct sockaddr_in* addr;
				addr = (struct sockaddr_in*)uni->Address.lpSockaddr;
				if(addr->sin_addr.s_addr == local_addr.s_addr){
					mtu = (int)cur_adapter->Mtu;
					break;
				}
			}
		}
	}
	if(adapters)
		free(adapters);
#endif

	return mtu;
}






#if __linux__
void* 
#elif __MINGW32__
__stdcall unsigned
#endif
net_read(void* _){
	(void)_;
	if(!sock){
		LOG_DEBUG("socket not initialized.");
#if __linux__
		return NULL;
#elif __MINGW32__
		return 0;
#endif
	}

	char buf[IP_MAXPACKET];
	struct ip* iph = (struct ip*)buf;
	struct timeval recv_time;
#if __linux__
	char ctlbuf[4096];
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg = {NULL, 0, &iov, 1, ctlbuf, sizeof(ctlbuf), 0};
#endif
	ssize_t recv_s;

for(;;usleep(1)){
#if __linux__
	if((recv_s = recvmsg(sock, &msg, 0)) < 0){
		if(errno == EAGAIN){
			struct timeval now;
			gettimeofday(&now, NULL);
			if(net_timeout > 0 && ELAPS(now, lastcomm)/1e6 > net_timeout){
				LOG_MESSAGE("net read timed out");
				exit(EXIT_SUCCESS);
			}else
				continue;
		}else
			LOG_ERROR("recvmsg");
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
#elif __MINGW32__
	if((recv_s = recv(sock, buf, IP_MAXPACKET, 0)) < 0){
		if(errno == EAGAIN){
			struct timeval now;
			gettimeofday(&now, NULL);
			if(net_timeout > 0 && ELAPS(now, lastcomm)/1e6 > net_timeout){
				LOG_MESSAGE("net read timed out");
				exit(EXIT_SUCCESS);
			}else
				continue;
		}else
			LOG_ERROR("recv");
	}
	gettimeofday(&recv_time, NULL);
#endif

	/* filter */
	u_short* sport = (u_short*)(buf + iph->ip_hl*4);
	u_short* dport = (u_short*)(buf + iph->ip_hl*4 + 2);
	if(recv_s < IPV4_H+2 || iph->ip_v != IPVERSION
	|| iph->ip_p != proto || recv_s - iph->ip_hl*4 < 2
	|| iph->ip_dst.s_addr != local_addr.s_addr
	|| iph->ip_src.s_addr != dst_addr.s_addr
	|| ntohs(*sport) != dst_port || ntohs(*dport) != local_port)
		continue;

	LOG_DEBUG("new datagram.");

	lastcomm = recv_time;

	/* new packet */
	if(packets_cur + 1 && packets_cur > packets_limit - 2){
		LOG_MESSAGE("packets limit reached");
		exit(EXIT_SUCCESS);
	}
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
	packets_cur++;
	packets_buf[packets_cur] = p;
}
#if __linux__
	return NULL;
#elif __MINGW32__
	return 0;
#endif
}







static
#if __linux__
void* 
#elif __MINGW32__
__stdcall unsigned
#endif
net_print(){
	size_t i = (size_t)-1;
	for(;;usleep(100)){
		if(i != packets_cur)
			packet_print(packets_buf[++i]);
	}
#if __linux__
	return NULL;
#elif __MINGW32__
	return 0;
#endif
}
void net_init(){
	if(sock){
		LOG_DEBUG("socket not initialized.");
		return;
	}

	proto = udp_mode ? IPPROTO_UDP : IPPROTO_TCP;

	/*XXX CAP_NET_RAW  */
	TRY( (int)(sock = socket(PF_INET, SOCK_RAW, proto)) );
	LOG_DEBUG("sock set up.");
	socklen_t optlen;

#if 0
	/* no linger */
	struct linger lg = { 0, 0 };
	TRY( setsockopt(sock, SOL_SOCKET, SO_LINGER, (char*)&lg, sizeof(lg)) );
#endif
	int on = 1;

#if __linux__
	/* high socket priority
	XXX CAP_NET_ADMIN 
	*/
	int sockpri = 1000;
	TRY( setsockopt(sock, SOL_SOCKET, SO_PRIORITY, (char*)&sockpri, sizeof(sockpri)) );

	/* recv timestamp */
	TRY( setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, (char*)&on, sizeof(on)) );
#endif

	/* set recv timeout: 1 usec */
	struct timeval rto = {0, 1};
	TRY( setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&rto, sizeof(rto)) );

	/* customize ip hdr */
	TRY( setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&on, sizeof(on)) );

	/* given local_addr, try to bind */
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(proto);
	local.sin_addr = local_addr;
	if(!local_addr.s_addr 
		&& bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0){
#if __linux__
		if(errno == EADDRNOTAVAIL){
#elif __MINGW32__
		if(errno == WSAEADDRNOTAVAIL){
#endif
			LOG_INFO("Non-local source addr: %s", inet_ntoa(local_addr));
			local.sin_addr.s_addr = INADDR_ANY;
			TRY( bind(sock, (struct sockaddr*)&local, sizeof(local)) );
		}else{
			LOG_ERROR("bind");
		}
	}

	/* autobind */
	struct sockaddr_in dst;
	dst.sin_family = AF_INET;
	dst.sin_port = IPPROTO_TCP;
	dst.sin_addr = dst_addr;
	TRY( connect(sock, (struct sockaddr*)&dst, sizeof(dst)) );
	LOG_DEBUG("sock connected.");

	/* get mtu */
	mtu = get_mtu();
	if(mtu < 0)
		LOG_FATAL("failed to get valid mtu");
	LOG_DEBUG("mtu is %d.", mtu);

	/* if local addr not given, fill in it with autobind result */
	optlen = sizeof(local);
	TRY( getsockname(sock, (struct sockaddr*)&local, &optlen) );
	if(!local_addr.s_addr)
		local_addr = local.sin_addr;
	LOG_INFO("bind addr: %s", inet_ntoa(local_addr));

	isn = rand();
	seq = isn;
	ip_id = rand()%65535 + 1;

	TRY( thread_create(&thrd_read, net_read) );
	TRY( thread_create(&thrd_print, net_print) );
}








void net_send(int _ttl, int f, u_long s, u_long a, char* p, int ps){
	if(!sock){
		LOG_DEBUG("socket not initialized.");
		return;
	}
	LOG_DEBUG("%d,%d,%lu,%lu,%u",_ttl,f,s,a,ps);
	static size_t lastbyte = 0;
	static struct timeval lastsent = {0, 0};
	if(!ps)p = NULL;
	if(p == NULL)ps = 0;
	if(IPV4_H + (udp_mode ? UDP_H : TCP_H) + ps > mtu)
		ps = mtu - IPV4_H - (udp_mode ? UDP_H : TCP_H);
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
			LOG_DEBUG("bandwidth throttling usleep: %.0f", bitrate_delay);
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

	if(packets_cur + 1 && packets_cur > packets_limit - 3){
		if(pkt)packet_free(pkt);
		LOG_MESSAGE("packets limit reached");
		exit(EXIT_SUCCESS);
	}
	packets_cur++;
	packets_buf[packets_cur] = pkt;
}

void net_cleanup(){
	if(!sock){
		LOG_DEBUG("socket not initialized.");
		return;
	}
#if __linux__
	close(sock);
#elif __MINGW32__
	closesocket(sock);
#endif
	LOG_DEBUG("socket closed.");
}
