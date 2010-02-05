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
#define DLT_EN10MB 1
#define BUFSIZE 65536

static FILE* dmp;
static char dmpbuf[BUFSIZE];

typedef struct {
	u_int32_t magic_number;
	u_int16_t version_major;
	u_int16_t version_minor;
	long thiszone;
	u_int32_t sigfigs;
	u_int32_t snaplen;
	u_int32_t network;
} pcaphdr;

typedef struct {
	u_int32_t ts_sec;
	u_int32_t ts_usec;
	u_int32_t incl_len;
	u_int32_t orig_len;
} pcaprec_hdr;


GQueue* dump_load(char* dumpfile){
	FILE* dmp;
	if(!dumpfile || !strcmp(dumpfile, "-")){
		dmp = stdin;
	}else{
		dmp = fopen(dumpfile, "r");
		if(dmp == NULL){
			ERROR("fopen");
			return NULL;
		}
	}
	pcaphdr h;
	if(fread(&h, sizeof(pcaphdr), 1, dmp) != 1){
		ERROR("read header");
		if(dmp != stdin)
			fclose(dmp);
		return NULL;
	}
	if(h.magic_number != TCPDUMP_MAGIC){
		ERR("not a pcap file");
		if(dmp != stdin)
			fclose(dmp);
		return NULL;
	}
	if(h.network != DLT_NULL
	&& h.network != DLT_EN10MB){
		ERR("unsupported link type");
		if(dmp != stdin)
			fclose(dmp);
		return NULL;
	}
	GQueue* packets = g_queue_new();
	pcaprec_hdr rh;
	char linkhdr[14];
	int linkhdr_s;
	char* buf = malloc(h.snaplen);
	if(h.network == DLT_NULL)
		linkhdr_s = 4;
	if(h.network == DLT_EN10MB)
		linkhdr_s = 14;
	while(!feof(dmp)){
		if(fread(&rh, sizeof(rh), 1, dmp) != 1
		|| rh.incl_len > rh.orig_len
		|| rh.incl_len > h.snaplen
		|| fread(linkhdr, sizeof(linkhdr_s), 1, dmp) != 1
		|| fread(buf, rh.incl_len - linkhdr_s, 1, dmp) != 1){
			if(!feof(dmp))ERR("packet broken");
			break;
		}
		struct timeval captime;
		captime.tv_sec = rh.ts_sec;
		captime.tv_usec = rh.ts_usec;
		packet* p = packet_new(buf, rh.incl_len - linkhdr_s, &captime);
		g_queue_push_tail(packets, p);
	}
	if(dmp != stdin)fclose(dmp);
	free(buf);
	return packets;
}
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

