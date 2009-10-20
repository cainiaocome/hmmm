#ifndef _UFW_TCPDUMP_H
#define _UFW_TCPDUMP_H

#include "packet.h"

int dump_init(char* dumpfile);
void dump_packet(packet*);
void dump_cleanup();

#endif /* _UFW_TCPDUMP_H */

