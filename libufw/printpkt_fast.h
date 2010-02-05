#ifndef _UFWUTIL_PRINTPKT_FAST_H_
#define _UFWUTIL_PRINTPKT_FAST_H_

#include <sys/time.h>
/**
 * print packet as a string
 * @param ip a valid ip packet
 * @param time timestamp of the packet
 * @param dir direction, 0 for incoming, 1 for outcoming
 * @param start_timeval pointer to a struct timeval of session start
 * @return length of the string, not including the trailing '\0'
 */
int packet_sprint_short_fast(char *s, const void *ip, const struct timeval *time, int dir);

#endif /* _UFWUTIL_PRINTPKT_FAST_H_ */
