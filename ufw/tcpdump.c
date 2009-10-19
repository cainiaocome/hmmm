#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include "net_config.h"
#include "packet.h"
#include "tcpdump.h"
#include "log.h"

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define DLT_NULL 0
extern size_t packets_limit;

void savedump(char* file, packet** buf, size_t start, size_t n){
	if(!file || !buf || !n)
		return;
	LOG_DEBUG("start:%d n:%d", start, n);
	struct {
		u_long magic_number;
		u_short version_major;
		u_short version_minor;
		long thiszone;
		u_long sigfigs;
		u_long snaplen;
		u_long network;
	} pcap_hdr = {TCPDUMP_MAGIC, 2, 4, 0, 0, IP_MAXPACKET, DLT_NULL}, fhdr;
	int has_hdr = 0;
	FILE* f;
	if(!strcmp(file, "-")){
		f = stdout;
		setbuf(stdout, NULL);
	}else{
		f = fopen(file, "a+b");
		if(f == NULL){
			LOG_MESSAGE("failed to open %s", file);
			return;
		}
		if(fread(&fhdr, sizeof(fhdr), 1, f) == 1 
		&& fhdr.magic_number == TCPDUMP_MAGIC)
				has_hdr = 1;
		if(!has_hdr){
				f = freopen(file, "wb", f);
				if(f == NULL){
					LOG_MESSAGE("failed to open %s", file);
					return;
				}
		}
	}
	if(!has_hdr && fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, f) != 1){
		LOG_MESSAGE("error when writing header");
		return;
	}
	size_t i;
	size_t pos;
	for(i = 0; i < n; i++){
		pos = (start + i)%packets_limit;
		struct {
			u_long ts_sec;
			u_long ts_usec;
			u_long incl_len;
			u_long orig_len;
		}pcaprec_hdr;
		u_long nullhdr = PF_INET;
		size_t nullhdr_s = 4;
		pcaprec_hdr.ts_sec = buf[pos]->time.tv_sec;
		pcaprec_hdr.ts_usec = buf[pos]->time.tv_usec;
		pcaprec_hdr.incl_len = buf[pos]->len + nullhdr_s;
		pcaprec_hdr.orig_len = buf[pos]->len + nullhdr_s;
		if(fwrite(&pcaprec_hdr, sizeof(pcaprec_hdr), 1, f) != 1
		|| fwrite(&nullhdr, nullhdr_s, 1, f) != 1
		|| fwrite(buf[pos]->hdr, buf[pos]->len, 1, f) != 1){
			LOG_MESSAGE("write error");
			fclose(f);
			return;
		}
		buf[pos] = NULL;
	}
	fclose(f);
}

packet* loaddump(char* file){
	(void)file;
	fprintf(stderr, "** loaddump() not implemented.\n");
	return NULL;
}
