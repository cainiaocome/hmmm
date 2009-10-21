/* a template */

#include "net_config.h"
#include <stdio.h>
#include <glib.h>
#include "packet.h"
#include "tcpdump.h"

tcp_seq isn, ian;
struct in_addr dst_addr;
struct timeval init_time;
int debug;

int istype1(packet* p){
	return ntohs(p->tcp->th_win) % 17 == 0 
		&& ntohs(p->hdr->ip_id) == 64
		&& !(ntohs(p->hdr->ip_off) & IP_DF);
}
int istype2(packet* p){
	return ntohs(p->hdr->ip_id) == (u_short)(-1 - ntohs(p->tcp->th_win)*13)
		&& (ntohs(p->hdr->ip_off) & IP_DF);
}
int main(int argc, char** argv){
	int i;
	GQueue* packets;
	for(i = 1; i < argc; i++){
		if(argc>2)printf("%s:\n", argv[i]);
		packets = dump_load(argv[i]);
		if(packets == NULL)
			continue;
		GList* t;
		int last_win = -1, this_win;
		for(t = packets->head; t; t = t->next){
			packet* p = t->data;
			if(p == NULL)
				continue;
			//packet_print(p);
			//do something
			if(istype2(p)){
				this_win = ntohs(p->tcp->th_win);
				if(last_win > 0)
					printf("%d.%06d %d\n", 
						(int)p->time.tv_sec, (int)p->time.tv_usec, this_win - last_win);
				last_win = this_win;
			}
		}
		if(argc>2)printf("\n");
	}
	return 0;
}
