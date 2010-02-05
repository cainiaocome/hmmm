#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "tcpdump.h"
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define DLT_NULL 0
#define DLT_EN10MB 1
#define	PF_INET		2

struct pcaphdr {
	u_int32_t magic_number;
	u_int16_t version_major;
	u_int16_t version_minor;
	long thiszone;
	u_int32_t sigfigs;
	u_int32_t snaplen;
	u_int32_t network;
};

struct pcaprechdr {
	u_int32_t ts_sec;
	u_int32_t ts_usec;
	u_int32_t incl_len;
	u_int32_t orig_len;
};

dump_t *dump_open(const char *pathname, const char *mode){
	FILE *fp;
	struct pcaphdr ph;
	size_t r;
	dump_t *dp;

	fp = fopen(pathname, mode);
	if(!fp)return NULL;
	if(strchr(mode, 'r') && !strchr(mode, 'w')){
		r = fread(&ph, sizeof(struct pcaphdr), 1, fp);
		if(r != 1)goto error;
		if(ph.magic_number != TCPDUMP_MAGIC)goto error;
		if(ph.network != DLT_NULL && ph.network != DLT_EN10MB)goto error;
		dp = malloc(sizeof(dump_t));
		if(!dp)goto error;
		dp->mode = 'r';
		dp->fp = fp;
		dp->network = ph.network;
		dp->snaplen = ph.snaplen;
	}else if(strchr(mode, 'w') && !strchr(mode, 'r')){
		dp = malloc(sizeof(dump_t));
		if(!dp)goto error;
		dp->mode = 'w';
		dp->fp = fp;
		dp->network = DLT_NULL;
		dp->snaplen = 65535;
		dp->header = 0;
	}else
		return NULL;
	return dp;
error:
	fclose(fp);
	return NULL;
}

int dump_read(dump_t *dp, void *ip, size_t limit, struct timeval *ts){
	struct pcaprechdr prh;
	int r;
	int linklen = 0;
	if(dp->mode != 'r')
		return 0;
	r = fread(&prh, sizeof(struct pcaprechdr), 1, dp->fp);
	if(r != 1)
		return 0;

	if(dp->network == DLT_NULL)
		linklen = 4;
	else if(dp->network == DLT_EN10MB)
		linklen = 14;

	r = fseek(dp->fp, linklen, SEEK_CUR);
	if(r < 0)return 0;

	if(limit > prh.incl_len - linklen)
		limit = prh.incl_len - linklen;
	r = fread(ip, limit, 1, dp->fp);
	if(r < 0)return 0;
	ts->tv_sec = prh.ts_sec;
	ts->tv_usec = prh.ts_usec;
	return 1;
}

int dump_write(dump_t *dp, const void *buf, size_t size, const struct timeval *ts){
	struct pcaphdr ph = {TCPDUMP_MAGIC, 2, 4, 0, 0, 65535, DLT_NULL};
	struct pcaprechdr prh;
	const struct iphdr *ip = buf;
	u_int32_t nullhdr = PF_INET;

	if(dp->mode != 'w')
		return 0;
	if(!dp->header){
		fwrite(&ph, sizeof(struct pcaphdr), 1, dp->fp);
		dp->header = 1;
	}

	if(!size || size > ntohs(ip->tot_len))
		size = ntohs(ip->tot_len);
	prh.ts_sec = ts->tv_sec;
	prh.ts_usec = ts->tv_usec;
	prh.incl_len = size + sizeof(nullhdr);
	prh.orig_len = size + sizeof(nullhdr);
	return fwrite(&prh, sizeof(prh), 1, dp->fp)
	&& fwrite(&nullhdr, sizeof(nullhdr), 1, dp->fp)
	&& fwrite(ip, size, 1, dp->fp);
}

int dump_close(dump_t *dp){
	if(!fclose(dp->fp))
		return -1;
	free(dp);
	return 0;
}
