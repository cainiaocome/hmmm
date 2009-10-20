#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <glib.h>

#include "net_config.h"
#include "packet.h"
#include "tcpdump.h"
#include "log.h"

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define DLT_NULL 0
#define BUFSIZE 65536

static FILE* dmp;
static char dmpbuf[BUFSIZE];

typedef struct {
	u_long magic_number;
	u_short version_major;
	u_short version_minor;
	long thiszone;
	u_long sigfigs;
	u_long snaplen;
	u_long network;
} pcaphdr;

typedef struct {
	u_long ts_sec;
	u_long ts_usec;
	u_long incl_len;
	u_long orig_len;
} pcaprec_hdr;


int dump_init(char* dumpfile){
	if(!dumpfile || dmp){
		DEBUG("null filename or double init");
		return -1;
	}
	if(!strcmp(dumpfile, "-")){
		dmp = stdout;
		setbuf(dmp, NULL);
	}else{
		dmp = fopen(dumpfile, "w");
		if(dmp == NULL){
			ERROR("fopen");
			return -1;
		}
		setbuf(dmp, dmpbuf);
	}
	pcaphdr h = {TCPDUMP_MAGIC, 2, 4, 0, 0, IP_MAXPACKET, DLT_NULL};
	if(fwrite(&h, sizeof(pcaphdr), 1, dmp) != 1){
		ERROR("fwrite");
		if(dmp != stdout)
			fclose(dmp);
		return -1;
	}
	return 0;
}
#if 0
void dump_save(){
	if(!packets)
		return;
	if(g_async_queue_length(packets) < 0)
		return;

	packet* p;
	while((p = g_async_queue_try_pop(packets))){
		pcaprec_hdr rh;
		u_long nullhdr = PF_INET;
		rh.ts_sec = p->time.tv_sec;
		rh.ts_usec = p->time.tv_usec;
		rh.incl_len = p->len + sizeof(nullhdr);
		rh.orig_len = p->len + sizeof(nullhdr);
		if(fwrite(&rh, sizeof(rh), 1, f) != 1
		|| fwrite(&nullhdr, sizeof(nullhdr), 1, f) != 1
		|| fwrite(p->hdr, p->len, 1, f) != 1){
			ERROR("fwrite");
		}
		packet_free(p);
	}
}
#endif
void dump_packet(packet* p){
	if(!p || !dmp)return;
	pcaprec_hdr rh;
	u_long nullhdr = PF_INET;
	rh.ts_sec = p->time.tv_sec;
	rh.ts_usec = p->time.tv_usec;
	rh.incl_len = p->len + sizeof(nullhdr);
	rh.orig_len = p->len + sizeof(nullhdr);
	if(fwrite(&rh, sizeof(rh), 1, dmp) != 1
	|| fwrite(&nullhdr, sizeof(nullhdr), 1, dmp) != 1
	|| fwrite(p->hdr, p->len, 1, dmp) != 1){
		ERROR("fwrite");
	}
}
void dump_cleanup(){
	if(!dmp)
		return;
	fflush(dmp);
	fclose(dmp);
	dmp = NULL;
}
