#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ufwutil.h"

struct experiment {
	struct timeval S, A, PA, R, RA;
	int Rnum, RAnum;
} data[500];
int base_port;

int lastrecv;

int sendhook(void *buf, const struct timeval *time, int dir, void *_){
	(void)_; (void)dir;
	struct iphdr *ip = buf;
	struct tcphdr *tcp = buf + (ip->ihl << 2);
	int i = ntohs(tcp->dest) - base_port;
	
	if(tcp->syn)
		data[i].S = *time;
	else if(tcp->ack && !tcp->psh)
		data[i].A = *time;
	else if(tcp->ack && tcp->psh)
		data[i].PA = *time;
	return 0;
}
int recvhook(void *buf, const struct timeval *time, int dir, void *_){
	(void)_; (void)dir;
	struct iphdr *ip = buf;
	struct tcphdr *tcp = buf + (ip->ihl << 2);
	int i = ntohs(tcp->dest) - base_port;

	lastrecv = time->tv_sec;
	if(tcp->rst && tcp->ack){
		if(data[i].RA.tv_sec == 0)
			data[i].RA = *time;
		data[i].RAnum++;
	}else if(tcp->rst)
		data[i].R = *time;
	return 0;
}

inline double elapse(struct timeval a, struct timeval b){
	return b.tv_sec - a.tv_sec + (b.tv_usec - a.tv_usec)/1e6;
}
int main(){
	ufw_sk *sk;
	char dest_str[20];
	int pos;
	char falun[] = "GET /falun HTTP/1.1\r\nHost: \r\n\r\n";

	snprintf(dest_str, 20, "64.233.172.%d", 0);
	u_int32_t dest = ufw_atoh(dest_str);//64.233.172.0

	base_port = 1;

	sk = ufw_socket(TCP, PRINT_ALL|FATAL|FILTER_ADDR);

	for(pos = 0; pos < 500; pos++){
		ufw_connect(sk, dest, base_port + pos);
		ufw_send_tcp(sk, SYN, 100, 0, 0, 0);
	}

	for(pos = 0; pos < 500; pos++){
		if(time(NULL) - lastrecv > 10)
			break;
		ufw_connect(sk, dest, base_port + pos);
		ufw_send_tcp(sk, ACK, 101, 201, 0, 0);
		ufw_send_tcp(sk, PSH|ACK, 101, 201, falun, sizeof(falun)-1);
		dsleep(1);
	}

	ufw_close(sk);

	for(pos = 0; pos < 500; pos++){
		if(data[pos].A.tv_sec == 0)continue;
		printf("%d.%06d %.6f %.6f %.6f %.6f %d %d\n", 
			(int)data[pos].A.tv_sec, (int)data[pos].A.tv_usec,
			elapse(data[pos].S, data[pos].A), elapse(data[pos].S, data[pos].PA),
			elapse(data[pos].S, data[pos].R), elapse(data[pos].S, data[pos].RA),
			data[pos].Rnum, data[pos].RAnum);
	}

	return 0;
}
