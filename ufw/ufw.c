#include "net_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <signal.h>
#include "log.h"
#include "packet.h"
#include "net.h"
#include "parse.h"
#include "tcpdump.h"

#define _NAME "ufw"
#define _DESCR "raw ip layer, manual tcp"
#define _DATE "Oct 9,13, 2009"
#define _VERSION "0.0.1"
#define USAGE "\
  ufw [OPTIONS] [-l] ADDR [PORT]\n\
  options:\n\
        -a                 inline signature analysis\n\
        -A                 non-ASCII payload as dot '.'\n\
        -b limit           bandwidth throttling. GgMmKk\n\
        -c count           packets count to receive (65535)\n\
        -D[D]              enable debug (twice for interpreter debug)\n\
        -d file            tcpdump to _file_\n\
        -h, -?             this\n\
        -i secs            default delay interval between lines (0.)\n\
        -l                 passive listening only, no sending\n\
        -p port            local port.\n\
        -P                 display payload\n\
        -s addr            local addr\n\
        -T ttl             default TTL\n\
        -u                 UDP\n\
        -v[v]              [very] verbose\n\
        -V                 version\n\
        -w secs            net read timeout (0 = +inf)\n\
        -x                 non-ASCII payload in hex escape\n"
/*
ADDR  := a.b.c.d/r | a.b.c | a.b | a
PORT  := [interger][-][integer] (1-65535 default)
*/

#define RAND() rand()
#define offset(cidr) (0xffffffffLL >> (cidr))
#define netname offset
#define netmask(cidr) (0xffffffffLL << (32-(cidr)))
#define hostnth(host, cidr, nth) \
    (((host) & netmask(cidr)) | ((nth) & netname(cidr)))
#define hostrand(host, cidr) \
    (((host) & netmask(cidr)) | (RAND() & netname(cidr)))
#define hostnext(host, cidr) \
    (((host) & netmask(cidr)) | (((host)+1) & netname(cidr)))

/* configs */
int verbose = 0;//-v
int debug = 0;
char* dumpfile = NULL;//-d
double line_interval = 0.;//-i
int listen_only = 0;//-l
packet** packets_buf = NULL;
size_t packets_limit = 65535;
size_t packets_cur = -1;

/* packet config */
extern int print_ascii;//-A
extern int payload_display;//
extern int print_hex;//-x
extern int analysis;

/* net config */
extern long long bandwidth;//-b
extern int ttl;//-T
extern int udp_mode;//-u
extern double net_timeout;//w
extern struct in_addr local_addr;//-s
extern u_short local_port;//-p
extern struct in_addr dst_addr;//ADDR
extern int dst_net;//ADDR
extern u_short dst_port;//PORT

#if __MINGW32__
static WSADATA wsaData;
#endif

int get_range(char* arg, int* lo, int* hi, int default_lo, int default_hi){
	char hyphen[] = "-";
	char* s = arg ? strdup(arg) : hyphen;
	char* p = strchr(s, '-');
	int lp, rp;
	if(!lo || !hi){
		lo = &lp;
		hi = &rp;
	}
	if(p){
		*p++ = 0;
		*lo = strlen(s) ? atoi(s) : default_lo;
		*hi = strlen(p) ? atoi(p) : default_hi;
	}else
		lp = rp = atoi(s);
	if(*lo > *hi){
		int t;
		t = *hi, *hi = *lo, *lo = t;
	}
	if(s != hyphen)
		free(s);
	return *lo != *hi ? rand()%(*hi-*lo+1)+*lo : *lo;
}


int resolv_addr(char* name, struct in_addr* addr){
	if(!name)
		return -1;
	struct addrinfo hints = {0, AF_INET, 0, 0, 0, NULL, NULL, NULL};
	struct addrinfo* result;
	struct addrinfo* cur;
	int r = getaddrinfo(name, NULL, &hints, &result);
	if(r){
		LOG_DEBUG("getaddrinfo: %s", gai_strerror(r));
		return -1;
	}
	int num = 0;
	for(cur = result; cur; cur = cur->ai_next)
		num++;
	if(num == 0){
		freeaddrinfo(result);
		return -1;
	}
	num = rand()%num;
	for(cur = result; cur && num--; cur = cur->ai_next);
	struct sockaddr_in* sa = (struct sockaddr_in*)cur->ai_addr;
	addr->s_addr = sa->sin_addr.s_addr;
	freeaddrinfo(result);
	return 0;
}

/*
www.google.com
1.2.3.4
1.2.3
www.google.com/24
1.2.3.4/24
*/
int get_addr(char* arg, struct in_addr* addr, int* net){
	char* s = strdup(arg);
	char* p = strchr(s, '/');
	if(p != NULL){
		*p++ = 0;
		if(0 == sscanf(p, "%u", net) || *net > 32 || *net < 0)
			*net = 32;
	}else
		*net = 32;
	if(resolv_addr(s, addr) < 0){
		if(p){
			free(s);
			return -1;
		}else{
			/* a[.b[.c]] */
			u_int a, b, c, n;
			a = b = c = 0;
			n = sscanf(s, "%u.%u.%u", &a, &b, &c);
			if(n > 0){
				addr->s_addr = htonl((a << 24) | (b << 16) | (c << 8));
				*net = n << 3;
			}else{
				free(s);
				return -1;
			}
		}
	}
	u_long a = ntohl(addr->s_addr);
	int nth, has_plus = 0;
	if(p != NULL){
		p = strchr(p, '+');
		if(1 == sscanf(p, "%d", &nth))
			has_plus = 1;
	}
	addr->s_addr = htonl(has_plus ? hostnth(a, *net, nth) : hostrand(a, *net));
	free(s);
	return 0;
}

void get_options(int argc, char** argv){
	int opt;
	while((opt = getopt(argc, argv, "?aAb:c:d:Dhi:lp:Ps:T:uvVw:x")) != -1)
		switch(opt){
			case 'a':
				analysis = 1;
				break;
			case 'A':
				print_ascii = 1;
				break;
			case 'b':{
				char c;
#if __linux__
				sscanf(optarg, "%llu%c", &bandwidth, &c);
#elif __MINGW32__ //m$ runtime mess
				sscanf(optarg, "%I64u%c", &bandwidth, &c);
#endif
				if(bandwidth < 0)bandwidth = 0;
				if(c == 'k' || c == 'K') bandwidth *= 1000;
				if(c == 'm' || c == 'M') bandwidth *= 1000000;
				if(c == 'g' || c == 'G') bandwidth *= 1000000000;
				break;
			}
			case 'c':
				packets_limit = atoi(optarg);
				break;
			case 'd':
				dumpfile = optarg;
				break;
			case 'D':
				debug++;
				break;
			case 'i':
				line_interval = strtod(optarg, NULL);
				break;
			case 'l':
				listen_only = 1;
				break;
			case 'p':
				local_port = get_range(optarg, NULL, NULL, 1, 65535);
				break;
			case 'P':
				payload_display = 1;
				break;
			case 's':
				if(resolv_addr(optarg, &local_addr) < 0)
					LOG_FATAL("Invalid argument for -s");
				break;
			case 'T':
				ttl = atoi(optarg);
				break;
			case 'u':
				udp_mode = 1;
				break;
			case 'v':
				verbose++;
				break;
			case 'V':
				printf("%s version %s, %s\n", _NAME, _VERSION, _DATE);
				exit(EXIT_SUCCESS);
			case 'w':
				net_timeout = atof(optarg);
				if(net_timeout < 0)
					net_timeout = 0;
				break;
			case 'x':
				print_hex = 1;
				break;
			case '?':
			case 'h':
			default:
				printf("%s - %s\n%s\n", _NAME, _DESCR, USAGE);
				exit(EXIT_SUCCESS);
		} /* while */

	if(optind >= argc)
		LOG_FATAL("Destination not specified.");

	/* get local addr and port*/
	if(!local_port)
		local_port = rand()%65535+1;
	LOG_INFO("source: %s:%d", inet_ntoa(local_addr), local_port);

	/* get destination addr and port */
	if(get_addr(argv[optind++], &dst_addr, &dst_net) < 0
	|| !dst_addr.s_addr)
		LOG_FATAL("Invalid destination");
	dst_port = get_range(argv[optind++], NULL, NULL, 1, 65535);
	LOG_INFO("dest: %s:%d", inet_ntoa(dst_addr), dst_port);

	/* sanity check */
	if(!finite(line_interval))
		LOG_FATAL("Invalid value of -i.");
	if(!finite(net_timeout))
		LOG_FATAL("Invalid value of -w.");
	if(print_ascii && print_hex)
		LOG_FATAL("-A and -x can't be both set.");

	packets_buf = calloc(packets_limit, sizeof(packet*));
	if(packets_buf == NULL)
		LOG_FATAL("failed to allocate memory");
}



void cleanup(){
	LOG_DEBUG("main cleanup");
	net_cleanup();

#if __MINGW32__
	if(wsaData.wVersion > 0)
		WSACleanup();
#endif

	if(dumpfile && packets_cur + 1)
		savedump(dumpfile, packets_buf, packets_cur + 1);

	/* free everything */
	size_t i;
	for(i = 0; packets_cur + 1 && i <= packets_cur; i++)
		packet_free(packets_buf[i]);
	if(packets_buf)
		free(packets_buf);
	fflush(stdout);
	fflush(stderr);
}

void sighandler(int sig){
	(void)sig;
	fprintf(stderr, "** exit on interrupt\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char** argv){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);

#if __MINGW32__
	if(WSAStartup(MAKEWORD(2,2), &wsaData))
		LOG_FATAL("WSAStartup failed");
#endif

	get_options(argc, argv);
	net_init();

	atexit(cleanup);
	signal(SIGINT, sighandler);

	if(!listen_only){
		if(net_timeout < 0)
			net_timeout = 5.;
#define LINEBS 65535
		char linebuf[LINEBS];

#if 0
		int flags = fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK;
		TRY( fcntl(STDIN_FILENO, F_SETFL, flags) )
#endif
		for(;;){
			if(fgets(linebuf, LINEBS, stdin)){
				size_t eol = 0;
				while(linebuf[eol] != '\n' && linebuf[eol] != '\r' && eol < LINEBS)
					eol++;
				usleep(line_interval*1e6);
				interpret(linebuf, eol);
			}else if(!feof(stdin)){
				LOG_ERROR("fread");
			}else usleep(1000000);
		}
	}else{
		for(;;)usleep(1);
	}

	return 0;
}
