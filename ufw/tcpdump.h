#ifndef _UFW_TCPDUMP_H
#define _UFW_TCPDUMP_H

#include "packet.h"

void savedump(char* file, packet* head);
packet* loaddump(char* file);

#endif /* _UFW_TCPDUMP_H */

