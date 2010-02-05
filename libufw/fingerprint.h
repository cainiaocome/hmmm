#ifndef _UFWUTIL_FINGERPRINT_H_
#define _UFWUTIL_FINGERPRINT_H_

int gfw_fingerprint(const void *ip);
int gfw_fingerprint_sprint(char *s, const void *ip);

#endif /* _UFWUTIL_FINGERPRINT_H_ */
