#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include "packet.h"
#include "tcpdump.h"
#include "log.h"

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define DLT_NULL 0
void savedump(char* file, packet* head){
	if(!file || !head)
		return;
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
			MESSAGE("failed to open %s", file);
			return;
		}
		if(fread(&fhdr, sizeof(fhdr), 1, f) == 1 
		&& fhdr.magic_number == TCPDUMP_MAGIC)
				has_hdr = 1;
		if(!has_hdr){
				f = freopen(file, "wb", f);
				if(f == NULL){
					MESSAGE("failed to open %s", file);
					return;
				}
		}
	}
	if(!has_hdr && fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, f) != 1){
		MESSAGE("error when writing header");
		return;
	}
	while(head){
		struct {
			u_long ts_sec;
			u_long ts_usec;
			u_long incl_len;
			u_long orig_len;
		}pcaprec_hdr;
		u_long nullhdr = PF_INET;
		size_t nullhdr_s = 4;
		pcaprec_hdr.ts_sec = head->time.tv_sec;
		pcaprec_hdr.ts_usec = head->time.tv_usec;
		pcaprec_hdr.incl_len = head->len + nullhdr_s;
		pcaprec_hdr.orig_len = head->len + nullhdr_s;
		if(fwrite(&pcaprec_hdr, sizeof(pcaprec_hdr), 1, f) != 1
		|| fwrite(&nullhdr, nullhdr_s, 1, f) != 1
		|| fwrite(head->hdr, head->len, 1, f) != 1){
			MESSAGE("write error");
			fclose(f);
			return;
		}
		head = head->next;
	}
	fclose(f);
}

packet* loaddump(char* file){
	(void)file;
	fprintf(stderr, "** loaddump() not implemented.\n");
	return NULL;
}
