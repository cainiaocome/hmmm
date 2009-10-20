#ifndef _UFW_LOG_H
#define _UFW_LOG_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern int verbose, debug;

#define DEBUG(format, ...)\
	if(debug)\
		fprintf(stderr, "-D %s:%d %s: " format "\n", __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__);

#define INFO(format, ...)\
	if(verbose >= 2)\
		fprintf(stderr, "-- " format "\n", ##__VA_ARGS__);

#define MESSAGE(format, ...)\
	if(verbose >= 1)\
		fprintf(stderr, "** " format "\n", ##__VA_ARGS__);

#define ERROR(s){\
	fprintf(stderr, "ufw: %s:%d: %s: %s\n", __FILE__, __LINE__, \
		s, strerror(errno));\
}

#define FATAL(s){\
	fprintf(stderr, "ufw: %s:%d: %s: %s\n", __FILE__, __LINE__, \
		s, strerror(errno));\
	exit(EXIT_FAILURE);\
}

#define DIE(s){\
	fprintf(stderr, "ufw: %s:%d: %s\n", __FILE__, __LINE__, s);\
	return -1;\
}

#endif /* _UFW_LOG_H */

