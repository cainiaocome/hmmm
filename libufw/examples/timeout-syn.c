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
	return 1;
}
int recvhook(void *buf, const struct timeval *time, int dir, void *_){
	(void)_; (void)dir;
	struct iphdr *ip = buf;
	struct tcphdr *tcp = buf + (ip->ihl << 2);
	int i = ntohs(tcp->source) - base_port;

	lastrecv = time->tv_sec;
	if(tcp->rst && tcp->ack){
		if(data[i].RA.tv_sec == 0)
			data[i].RA = *time;
		data[i].RAnum++;
	}else if(tcp->rst){
		data[i].R = *time;
		data[i].Rnum++;
	}
	return 1;
}

inline double elapse(struct timeval a, struct timeval b){
	return b.tv_sec - a.tv_sec + (b.tv_usec - a.tv_usec)/1e6;
}
int main(){
	ufw_sk *sk;
	char dest_str[20];
	int pos;
	char falun[] = "GET /falun HTTP/1.1\r\nHost: \r\n\r\n";

	srand(time(NULL));
	snprintf(dest_str, 20, "64.233.172.%d", (int)time(NULL)/60%256);
	u_int32_t dest = ufw_atoh(dest_str);//64.233.172.0

	base_port = 50000;

	sk = ufw_socket(TCP, PRINT_ALL|FATAL|FILTER_ADDR);

	ufw_set_limit_packet(sk, 1000, SYN);
	ufw_inserthook(sk, HOOK_RECV, recvhook, NULL);
	ufw_inserthook(sk, HOOK_SEND, sendhook, NULL);

	for(pos = 0; pos < 500; pos++){
		ufw_connect(sk, dest, base_port + pos);
		ufw_send_tcp(sk, SYN, 100, 0, NULL, 0);
	}

	for(pos = 0; pos < 500; pos++){
		if(lastrecv && time(NULL) - lastrecv > 10)
			break;
		ufw_connect(sk, dest, base_port + pos);
		ufw_send_tcp(sk, ACK, 101, 201, 0, 0);
		ufw_send_tcp(sk, PSH|ACK, 101, 201, falun, sizeof(falun)-1);
		dsleep(1);
	}

	ufw_close(sk);

	for(pos = 0; pos < 500; pos++){
		if(data[pos].PA.tv_sec == 0)continue;
		printf("%d.%06d %.6f %.6f", 
			(int)data[pos].A.tv_sec, (int)data[pos].A.tv_usec,
			elapse(data[pos].S, data[pos].A), elapse(data[pos].S, data[pos].PA));
		if(data[pos].R.tv_sec)
			printf(" %.6f", elapse(data[pos].S, data[pos].R));
		else
			printf(" ?");
		if(data[pos].RA.tv_sec)
			printf(" %.6f", elapse(data[pos].S, data[pos].RA));
		else
			printf(" ?");
		printf(" %d %d\n", data[pos].Rnum, data[pos].RAnum);
	}

	return 0;
}
