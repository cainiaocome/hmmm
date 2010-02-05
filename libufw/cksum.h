#ifndef _UFWUTIL_CKSUM_H_
#define _UFWUTIL_CKSUM_H_


int tcp_cksum(const void *buf, size_t len);
int udp_cksum(const void *buf, size_t len);
#endif /* _UFWUTIL_CKSUM_H_ */
