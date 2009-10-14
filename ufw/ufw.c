#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "packet.h"
#include "net.h"
#include "parse.h"
#include "tcpdump.h"

#define _NAME "ufw"
#define _DESCR "raw ip layer tool"
#define _DATE "Oct 9,13, 2009"
#define _VERSION "0.0.1"
#define USAGE "\
  ufw [OPTIONS] [-l] ADDR [PORT]\n\
  ufw [OPTIONS] -r file ADDR [PORT]\n\
  options:\n\
        -A                 non-ASCII payload as dot '.'\n\
        -b limit           bandwidth throttling. GgMmKk\n\
        -D[D]              enable debug (twice for interpreter debug)\n\
        -d file            tcpdump to _file_\n\
        -h, -?             this\n\
        -i secs            default delay interval between lines (0.)\n\
        -l                 passive listening only, no sending\n\
        -n nth             Nth addr in the addr range\n\
        -p port            local port.\n\
        -P                 display payload\n\
        -s addr            local addr\n\
        -T ttl             default TTL\n\
        -u                 UDP\n\
        -v[vv]             [vvery] verbose\n\
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
int addr_nth = 0;

/* packet config */
extern int print_ascii;//-A
extern int payload_display;//
extern int print_hex;//-x

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

packet* packets_head = NULL;
packet* packets_tail = NULL;
int send_delay;


int get_range(char* arg, int* lo, int* hi, int default_lo, int default_hi){
	char hyphen[] = "-";
	char* s = arg ? strdupa(arg) : hyphen;
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
	return *lo != *hi ? rand()%(*hi-*lo+1)+*lo : *lo;
}

in_addr_t get_addr(char* arg, struct in_addr* addr, int* net, int nth){
	char* s = strdupa(arg);
	char* p = strchr(s, '/');
	if(p){
		/* cidr */
		*p++ = 0;
		if(!inet_aton(s, addr))
			FATAL("Invalid destination addr")
		else if(0 == sscanf(p, "%u", net))
			*net = -1;
	}else{
		/* a[.b[.c[.d]]] */
		u_char a, b, c, d, n;
		a = b = c = d = 0;
		n = sscanf(s, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
		if(n > 0){
			addr->s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
			*net = n << 3;
		}
	}
	in_addr_t a = ntohl(addr->s_addr);
	int n = *net;
	return htonl(n==-1 ? hostrand(a, n) : hostnth(a, n, nth));
}

void get_options(int argc, char** argv){
	int opt;
	while((opt = getopt(argc, argv, "?Ab:d:Dhi:ln:p:Ps:T:uvVw:x")) != -1)
		switch(opt){
			case 'A':
				print_ascii = 1;
				break;
			case 'b':{
				char c;
				sscanf(optarg, "%llu%c", &bandwidth, &c);
				if(bandwidth < 0)bandwidth = 0;
				if(c == 'k' || c == 'K') bandwidth *= 1000;
				if(c == 'm' || c == 'M') bandwidth *= 1000000;
				if(c == 'g' || c == 'G') bandwidth *= 1000000000;
				break;
			}
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
			case 'n':
				addr_nth = atoi(optarg);
				break;
			case 'p':
				local_port = get_range(optarg, NULL, NULL, 1, 65535);
				break;
			case 'P':
				payload_display = 1;
				break;
			case 's':
				if(!inet_aton(optarg, &local_addr))
					FATAL("Invalid argument for -s");
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
		FATAL("Destination not specified.");

	/* get local addr and port*/
	if(!local_port)
		local_port = rand()%65535+1;
	INFO("source: %s:%d", inet_ntoa(local_addr), local_port);

	/* get destination addr and port */
	dst_addr.s_addr = get_addr(argv[optind++], &dst_addr, &dst_net, addr_nth);
	dst_port = get_range(argv[optind++], NULL, NULL, 1, 65535);
	INFO("dest: %s:%d", inet_ntoa(dst_addr), dst_port);

	/* sanity check */
	if(!dst_addr.s_addr || dst_net < 0)
		FATAL("Invalid destination.");
	if(!isfinite(line_interval))
		FATAL("Invalid value of -i.");
	if(!isfinite(net_timeout))
		FATAL("Invalid value of -w.");
	if(print_ascii && print_hex)
		FATAL("-A and -x can't be both set.");
}



void cleanup(){
	DEBUG("main cleanup");
	net_cleanup();

	if(dumpfile && packets_head)
		savedump(dumpfile, packets_head);

	/* free everything */
	packet* cur = packets_head;
	while(cur){
		packet* p = cur->next;
		packet_free(cur);
		cur = p;
	}
	packets_head = cur;
}

void sighandler(int sig){
	(void)sig;
	fprintf(stderr, "** exit on interrupt\n");
	exit(0);
}

int main(int argc, char** argv){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);

	get_options(argc, argv);
	net_init();

	atexit(cleanup);
	signal(SIGINT, sighandler);

	if(!listen_only){
		if(net_timeout < 0)
			net_timeout = 5.;
#define LINEBS 65535
		char linebuf[LINEBS];

		int flags = fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK;
		TRY( fcntl(STDIN_FILENO, F_SETFL, flags) )
		for(;;){
			if(fgets(linebuf, LINEBS, stdin)){
				size_t eol = 0;
				while(linebuf[eol] != '\n' && linebuf[eol] != '\r' && eol < LINEBS)
					eol++;
				send_delay += line_interval*1e6;
				interpret(linebuf, eol);
			}else if(errno == EAGAIN){
				net_read();
			}else
				ERROR("fread");
		}
	}else{
		for(;;)
			net_read();
	}

	return 0;
}
