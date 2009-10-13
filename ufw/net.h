#ifndef _UFW_NET_H
#define _UFW_NET_H

#include <sys/types.h>
void net_cleanup();
void net_send(int _ttl, int f, u_long s, u_long a, char* p, size_t ps);
void net_read();
void net_init();

#endif /* _UFW_NET_H */
