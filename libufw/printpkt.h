#ifndef _UFWUTIL_PRINTPKT_H_
#define _UFWUTIL_PRINTPKT_H_

#include <sys/time.h>
/**
 * print packet as a string
 * @param ip a valid ip packet
 * @param time timestamp of the packet
 * @param dir direction, 0 for incoming, 1 for outcoming
 * @param start_timeval pointer to a struct timeval of session start
 * @return length of the string, not including the trailing '\0'
 */
int packet_snprint_short(char *s, int len, const void *ip, const struct timeval *time, int dir, void *start_timeval);
int packet_snprint_human(char *s, int len, const void *ip, const struct timeval *time, int dir, void *start_timeval);
int packet_snprint_machine(char *s, int len, const void *ip, const struct timeval *time, int dir, void *start_timeval);

#endif /* _UFWUTIL_PRINTPKT_H_ */
