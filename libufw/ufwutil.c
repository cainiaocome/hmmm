#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>

#include "ufwutil.h"
#include "printpkt_fast.h"
#include "tcpdump.h"
#include "cksum.h"

struct node {
	void *data;
	struct node *prev, *next;
};

struct hookinfo {
	ufw_hook func;
	void *user;
};

static int is_ufw_sigio_handler;
static struct node *ufwsk_list;
static int seeded = 0;

#define die(fmt, ...) error(errno, errno,  "%s: " fmt, __func__, ##__VA_ARGS__)


static void ufw_sigio_handler(int, siginfo_t *, void *);
static inline int build_tcp(ufw_sk *sk, u_int8_t flags, u_int32_t seq, u_int32_t ack, const void *pl, int pls);
static inline int build_udp(ufw_sk *sk, const void *pl, int pls);
static inline int ufw_send(ufw_sk *sk);
static inline int ufw_recv(ufw_sk *sk);
static inline int print_packet(const void *ip, const struct timeval *time, int dir);

ufw_sk *ufw_socket(int proto, int opts){
	ufw_sk *sk;
	struct node *cur;
	struct linger lg = { 0, 0 };
	struct timeval now;
	char filename[100];
	int on = 1;
	int fd;
	dump_t *dp = NULL;
	struct sigaction handler;

	if(proto != IPPROTO_TCP && proto != IPPROTO_UDP){
		errno = EINVAL;
		if(opts & FATAL)die("proto");
		return NULL;
	}

	fd = socket(PF_INET, SOCK_RAW, proto);
	if(fd < 0){
		if(opts & FATAL)die("socket");
		return NULL;
	}
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on));
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

	if(fcntl(fd, F_SETOWN, getpid()) < 0){
		if(opts & FATAL)die("fcntl");
		return NULL;
	}

	if(fcntl(fd, F_SETFL, O_NONBLOCK | O_ASYNC) < 0){
		if(opts & FATAL)die("fcntl");
		return NULL;
	}

	if(fcntl(fd, F_SETSIG, SIGIO) < 0){
		if(opts & FATAL)die("fcntl");
		return NULL;
	}

	if(opts & DUMP_AUTONAME){
		gettimeofday(&now, NULL);
		snprintf(filename, 100, "/tmp/%d.%06d.pcap", (int)now.tv_sec, (int)now.tv_usec);
		dp = dump_open(filename, "w");
		if(!dp){
			if(opts & FATAL)die("%s", filename);
			return NULL;
		}
	}

	cur = malloc(sizeof(struct node) + sizeof(ufw_sk));
	if(!cur){
		if(opts & FATAL)die("malloc");
		return NULL;
	}

	sk = (void *)cur + sizeof(struct node);
	cur->data = sk;
	cur->next = ufwsk_list;
	cur->prev = NULL;
	ufwsk_list = cur;

	sk->fd = fd;
	sk->opts = opts;
	sk->ttl = IPDEFTTL;
	sk->proto = proto;
	sk->saddr = sk->daddr = 0;
	sk->sport = sk->dport = 0;
	sk->window = TCP_MAXWIN;
	sk->first_packet.tv_sec = 0;
	sk->first_packet.tv_usec = 0;
	sk->limit_packet = 0;
	sk->limit_packet_flags = 0;
	sk->limit_byte = 0;
	sk->received = 0;
	sk->dump = dp;

	if(!(opts & SIGIO_MANUAL) && !is_ufw_sigio_handler){
		is_ufw_sigio_handler = 1;
		handler.sa_sigaction = ufw_sigio_handler;
		sigfillset(&handler.sa_mask);
		handler.sa_flags = SA_SIGINFO;
		sigaction(SIGIO, &handler, NULL);
	}

	return sk;
}

ufw_sk *ufw_getsk(int fd){
	struct node *cur;
	ufw_sk *sk;
	for(cur = ufwsk_list; cur; cur = cur->next){
		sk = cur->data;
		if(sk->fd == fd)
			return sk;
	}
	return NULL;
}

static void ufw_sigio_handler(int sig, siginfo_t *si, void *_){
	(void)sig;
	(void)_;
	ufw_sk *sk;

	if(si->si_code != POLL_IN){
		return;
	}
	sk = ufw_getsk(si->si_fd);
	if(sk)
		ufw_recv(sk);
}

int ufw_inserthook(ufw_sk *sk, int whence, ufw_hook hk, void *user){
	struct node **hookchain;
	struct hookinfo *hki;
	struct node *cur;

	if(!sk){
		errno = EBADF;
		return -1;
	}

	if(whence == HOOK_RECV)
		hookchain = &sk->recvhook;
	else if(whence == HOOK_SEND)
		hookchain = &sk->sendhook;
	else{
		errno = EINVAL;
		if(sk->opts & FATAL)die("whence");
		return -1;
	}

	cur = malloc(sizeof(struct node) + sizeof(struct hookinfo));
	if(!cur){
		if(sk->opts & FATAL)die("malloc");
		return -1;
	}
	hki = (void *)cur + sizeof(struct node);
	hki->func = hk;
	hki->user = user;
	cur->data = hki;
	cur->prev = NULL;
	cur->next = *hookchain;
	*hookchain = cur;

	return 1;
}

int ufw_removehook(ufw_sk *sk, int whence, ufw_hook hk){
	struct node **hookchain;
	struct hookinfo *hki;
	struct node *cur;

	if(!sk){
		errno = EBADF;
		return -1;
	}

	if(whence == HOOK_RECV)
		hookchain = &sk->recvhook;
	else if(whence == HOOK_SEND)
		hookchain = &sk->sendhook;
	else{
		errno = EINVAL;
		if(sk->opts & FATAL)die("whence");
		return -1;
	}

	for(cur = *hookchain; cur; cur = cur->next){
		hki = cur->data;
		if(hki->func == hk){
			if(cur->prev)
				cur->prev->next = cur->next;
			else
				*hookchain = cur->next;
			if(cur->next)
				cur->next->prev = cur->prev;
			free(cur);
			return 1;
		}
	}

	return 0;
}

int ufw_connect(ufw_sk *sk, u_int32_t daddr, u_int16_t dport){
	struct sockaddr_in addr;
	socklen_t ol;
	struct timeval t;
	int s;

	if(!sk){
		errno = EBADF;
		return -1;
	}

	if(htonl(daddr) == sk->daddr){
		sk->dport = htons(dport);
		return 0;
	}
	sk->daddr = htonl(daddr);
	sk->dport = htons(dport);
	addr.sin_family = AF_INET;
	addr.sin_port = sk->proto;
	addr.sin_addr.s_addr = sk->daddr;
	
	s = connect(sk->fd, (struct sockaddr *)&addr, sizeof(addr));
	if(s < 0){
		if(sk->opts & FATAL)die("connect");
		return -1;
	}

	ol = sizeof(addr);
	s = getsockname(sk->fd, (struct sockaddr *)&addr, &ol);
	if(s < 0){
		if(sk->opts & FATAL)die("connect");
		return -1;
	}

	sk->saddr = addr.sin_addr.s_addr;
	if(!seeded){
		seeded = 1;
		gettimeofday(&t, NULL);
		srand48(t.tv_sec*t.tv_usec);
	}
	sk->sport = lrand48()%65535 + 1;

	return 0;
}

int ufw_set_source(ufw_sk *sk, u_int32_t saddr, u_int16_t sport){
	int s;
	struct sockaddr_in addr;

	if(!sk){
		errno = EBADF;
		return -1;
	}

/* XXX bug here
	addr.sin_family = AF_UNSPEC;
	s = connect(sk->fd, (struct sockaddr *)&addr, sizeof(addr));
	if(s < 0){
		if(sk->opts & FATAL)die("connect");
		return -1;
	}
*/
	if(saddr)
		sk->saddr = htonl(saddr);
	sk->sport = htons(sport);
	return 0;
}

int ufw_set_window(ufw_sk *sk, u_int16_t window){
	if(!sk){
		errno = EBADF;
		return -1;
	}

	sk->window = htons(window);
	return 0;
}

int ufw_set_ttl(ufw_sk *sk, u_int8_t ttl){
	if(!sk){
		errno = EBADF;
		return -1;
	}

	sk->ttl = ttl;
	return 0;
}

int ufw_set_limit_packet(ufw_sk *sk, int limit, int flags){
	if(!sk){
		errno = EBADF;
		return -1;
	}

	sk->limit_packet = limit;
	sk->limit_packet_flags = flags;

	return 0;
}

int ufw_set_limit_byte(ufw_sk *sk, int limit){
	if(!sk){
		errno = EBADF;
		return -1;
	}

	sk->limit_byte = limit;

	return 0;
}

int ufw_set_dumpfile(ufw_sk *sk, const char *pathname){
	if(sk->dump)
		return 0;
	sk->dump = dump_open(pathname, "w");
	if(!sk->dump){
		if(sk->opts & FATAL)die("%s", pathname);
		return -1;
	}
	return 0;
}

static inline int build_tcp(ufw_sk *sk, u_int8_t flags, u_int32_t seq, u_int32_t ack, const void *pl, int pls){
	struct iphdr *ip;
	struct tcphdr *tcp;
	int hlen;

	ip = (struct iphdr *)sk->buf;
	tcp = (struct tcphdr *)(sk->buf + sizeof(struct iphdr));
	if(!pls)pl = NULL;
	if(pl == NULL)pls = 0;

	hlen = sizeof(struct iphdr) + sizeof(struct tcphdr);
	if(hlen + pls > IP_MAXPACKET){
		errno = EMSGSIZE;
		if(sk->opts & FATAL)die("payload");
		return -1;
	}

	ip->ihl = sizeof(struct iphdr) >> 2;
	ip->version = IPVERSION;
	ip->tos = 0;
	ip->tot_len = htons(hlen + pls);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = sk->ttl;
	ip->protocol = sk->proto;
	ip->saddr = sk->saddr;
	ip->daddr = sk->daddr;
	tcp->source = sk->sport;
	tcp->dest = sk->dport;
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(ack);
	tcp->res1 = 0;
	tcp->doff = sizeof(struct tcphdr) >> 2;
	sk->buf[sizeof(struct iphdr) + 13] = flags;
	tcp->window = sk->window;
	tcp->urg_ptr = 0;
	if(pl != NULL)
		memcpy(sk->buf + hlen, pl, pls);
	tcp->check = tcp_cksum(sk->buf, sizeof(struct tcphdr) + pls);

	return hlen + pls;
}

static inline int build_udp(ufw_sk *sk, const void *pl, int pls){
	struct udphdr *udp;
	int hlen;

	udp = (struct udphdr *)(sk->buf + pls);
	if(!pls)pl = NULL;
	if(pl == NULL)pls = 0;

	hlen = sizeof(struct udphdr);
	if(hlen + pls > IP_MAXPACKET){
		errno = EMSGSIZE;
		if(sk->opts & FATAL)die("payload");
		return -1;
	}

	udp->source = sk->sport;
	udp->dest = sk->dport;
	udp->len = htons(hlen + pls);
	if(pl != NULL)
		memcpy(sk->buf + hlen, pl, pls);
	udp->check = udp_cksum(sk->buf, hlen + pls);

	return hlen + pls;
}
int ufw_send_tcp(ufw_sk *sk, u_int8_t flags, u_int32_t seq, u_int32_t ack, const void *pl, int pls){
	if(!sk){
		errno = EBADF;
		return -1;
	}

	if(sk->proto != IPPROTO_TCP){
		errno = EINVAL;
		if(sk->opts & FATAL)die("protocol");
		return -1;
	}

	if(build_tcp(sk, flags, seq, ack, pl, pls) < 0)
		return -1;

	return ufw_send(sk);
}
int ufw_send_udp(ufw_sk *sk, const void *pl, int pls){
	if(!sk){
		errno = EBADF;
		return -1;
	}

	if(sk->proto != IPPROTO_UDP){
		errno = EINVAL;
		if(sk->opts & FATAL)die("protocol");
		return -1;
	}

	if(build_udp(sk, pl, pls) < 0)
		return -1;

	return ufw_send(sk);
}

int ufw_repeat(ufw_sk *sk){
	return ufw_send(sk);
}
static int ufw_send(ufw_sk *sk){
	struct timeval time;
	struct node *cur;
	struct hookinfo *hki;
	struct iphdr *ip;
	struct sockaddr_in addr;
	double delay;
	int r;
	static int first = 1;
	static struct timeval last;
	size_t len;

	if(!sk){
		errno = EBADF;
		return -1;
	}

	ip = (struct iphdr *)sk->buf;
	delay = 0;


	addr.sin_family = AF_INET;
	addr.sin_port = sk->proto;
	addr.sin_addr.s_addr = sk->daddr;
	len = ntohs(ip->tot_len);
	r = sendto(sk->fd, sk->buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));

	gettimeofday(&time, NULL);

	if(!first){
		delay = 0;
		if(sk->limit_byte > 0)
			delay = (double)len/sk->limit_byte;

		if(sk->limit_packet > 0 
		&& (ip->protocol == IPPROTO_UDP 
			|| (sk->limit_packet_flags & sk->buf[(ip->ihl << 2) + 13]))
		&& 1./sk->limit_packet > delay)
			delay = 1./sk->limit_packet;

		delay -= time.tv_sec - last.tv_sec + (time.tv_usec - last.tv_usec)/1e6;
		if(delay > 0)
			dsleep(delay);
	}
	first = 0;
	last = time;

	if(!sk->first_packet.tv_sec)
		sk->first_packet = time;
	if(r < 0){
		if(sk->opts & FATAL)die("sendto");
		return -1;
	}

	for(cur = sk->sendhook; cur; cur = cur->next){
		hki = cur->data;
		if(!hki->func(sk->buf, &time, 1, hki->user))
			return r;
	}

	if((sk->opts & DUMP_SEND) && sk->dump)
		dump_write(sk->dump, sk->buf, 0, &time);

	time.tv_sec -= sk->first_packet.tv_sec;
	time.tv_usec -= sk->first_packet.tv_usec;
	if(time.tv_usec < 0)time.tv_usec += 1000000;

	if(sk->opts & PRINT_SEND)
		print_packet(sk->buf, &time, 1);

	return r;
}



static inline int ufw_recv(ufw_sk *sk){
	struct cmsghdr* cmsg;
	char ctlbuf[4096];
	struct iovec iov;
	struct msghdr msg = {NULL, 0, &iov, 1, ctlbuf, sizeof(ctlbuf), 0};
	ssize_t s;
	struct node *cur;
	struct hookinfo *hki;
	struct timeval time;
	struct iphdr *ip;

	if(!sk){
		errno = EBADF;
		return -1;
	}

	iov.iov_base = sk->buf;
	iov.iov_len = sizeof(sk->buf);
	ip = (struct iphdr *)sk->buf;

	for(;;){
	next:
		s = recvmsg(sk->fd, &msg, MSG_WAITALL);
		if(s < 0){
			if(errno == EAGAIN)
				return 0;
			else {
				if(sk->opts & FATAL)die("recvmsg");
				return -1;
			}
		}

		/* filter */
		if((sk->opts & FILTER_SADDR) && ip->daddr != sk->saddr)
			continue;
		if((sk->opts & FILTER_DADDR) && ip->saddr != sk->daddr)
			continue;
		if((sk->opts & FILTER_SPORT) 
			&& *(u_int16_t *)(sk->buf + (ip->ihl << 2) + 2) != sk->sport)
			continue;
		if((sk->opts & FILTER_DPORT) 
			&& *(u_int16_t *)(sk->buf + (ip->ihl << 2)) != sk->dport)
			continue;

		sk->received = 1;

		/* get timestamp */
		for(cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
			if(cmsg->cmsg_level == SOL_SOCKET
			&& cmsg->cmsg_type == SO_TIMESTAMP
			&& cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timeval))){
				time = *(struct timeval *)CMSG_DATA(cmsg);
				break;
			}

		if(!sk->first_packet.tv_sec)
			sk->first_packet = time;

		for(cur = sk->recvhook; cur; cur = cur->next){
			hki = cur->data;
			if(!hki->func(sk->buf, &time, 1, hki->user))
				goto next;
		}

		if((sk->opts & DUMP_RECV) && sk->dump)
			dump_write(sk->dump, sk->buf, 0, &time);

		time.tv_sec -= sk->first_packet.tv_sec;
		time.tv_usec -= sk->first_packet.tv_usec;
		if(time.tv_usec < 0)time.tv_usec += 1000000;

		if(sk->opts & PRINT_RECV)
			print_packet(sk->buf, &time, 0);
	}

	return -1;//never
}

static inline int print_packet(const void *ip, const struct timeval *time, int dir){
	char buf[4096];
	int len, written, n;

	len = packet_sprint_short_fast(buf, ip, time, dir);//XXX no protection of overflow
	buf[len++] = '\n';

	for(written = 0; written < len; written += n){
		n = write(STDOUT_FILENO, buf + written, len - written);
		if(n < 0 && n != EINTR)
			return -1;
	}

	return len;
}

void ufw_close(ufw_sk *sk){
	struct node *cur, *next;

	if(!sk)
		return;

	while(close(sk->fd) < 0 && errno == EINTR);
	for(cur = sk->recvhook; cur; cur = next){
		next = cur->next;
		free(cur);
	}
	for(cur = sk->sendhook; cur; cur = next){
		next = cur->next;
		free(cur);
	}
	if(sk->dump)
		dump_close(sk->dump);

	for(cur = ufwsk_list; cur; cur = cur->next)
		if(sk == cur->data){
			if(cur->prev)
				cur->prev->next = cur->next;
			else
				ufwsk_list = cur->next;
			if(cur->next)
				cur->next->prev = cur->prev;
			free(cur);
			return;
		}
}

void dsleep(double sec){
	struct timespec r;
	r.tv_sec = sec;
	r.tv_nsec = (sec - (int)sec)*1e9;
	while(nanosleep(&r, &r) == -1);
}

u_int32_t ufw_atoh(const char *ip){
	return ntohl(inet_addr(ip));
}

int ufw_pause(ufw_sk *sk){
	if(!sk){
		errno = EBADF;
		return -1;
	}

	for(sk->received = 0; !sk->received; pause());

	return 0;
}

int ufw_sleep(ufw_sk *sk, unsigned int seconds){
	struct timespec r;
	int ret;
	if(!sk){
		errno = EBADF;
		return -1;
	}

	r.tv_sec = seconds;
	r.tv_nsec = 0;

	for(sk->received = 0; !sk->received; ){
		ret = nanosleep(&r, &r);
		if(ret == 0)
			break;
	}

	return ret;
}

int ufw_bindtodev(ufw_sk *sk, const char *name){
	return setsockopt(sk->fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name));
}
