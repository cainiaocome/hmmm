#ifndef _UFW_NET_H
#define _UFW_NET_H

#include <sys/types.h>
void net_cleanup();
int net_send(int _ttl, int f, u_long s, u_long a, char* p, int ps);
int net_init();

#endif /* _UFW_NET_H */
