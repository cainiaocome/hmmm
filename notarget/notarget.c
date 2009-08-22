#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <glib.h>
#include <libnet.h>

#define _NAME "notarget"
#define _DESCR "A demo of insertion attack against IPS based on TTL crafting"
#define _VERSION "0.0.2"
/*
 * Falun Conjecture: every case-insensitive string that causes 
   GFW attacks is longer than "falun".
Try to prove or falsify. */
#define _DATE "Aug 17 2009"
#define _COPYING "Copyright (c) 2009, KLZ-grad. License: BSD."


typedef struct {
	gulong daddr;
	gushort sport;
	gushort dport;
	guint lrt;
	gulong seq;
	gushort id;
	GString* name;
	GTimer* timer;
	gboolean sent;
	gboolean traced;
	guint reply;
} job_t;

typedef struct {
	guchar hop;
	guint addr;
	gushort port;
	GString* name;
	guint time;
} record_t;



gpointer recv_thread(gpointer);

void inject(struct libnet_ipv4_hdr*, struct libnet_tcp_hdr*, record_t*);
void trace(job_t*);

void logsync();

char* addr2name(guint);
void print_packet(struct libnet_ipv4_hdr*, struct libnet_tcp_hdr*);

void packet_free(gpointer);
job_t* job_new(gulong addr, gushort port);
void job_free(gpointer);
record_t* record_new(job_t*);
void record_free(gpointer);

void cleanup();
void init(int argc, char** argv);
void sigh(int _);



gboolean recv_continue;
gboolean main_continue;

GThread* recvt;
GQueue* jobs;
GAsyncQueue* packet_queue;
GHashTable* ip2hop;
G_LOCK_DEFINE(ip2hop);
GTimer* update;
GRand* rnd;
GError* gerr;

libnet_t* l;
char errbuf[LIBNET_ERRBUF_SIZE];
libnet_ptag_t tcp;
libnet_ptag_t ip;

gulong myip;

/* conf vars */
guint cfg_maxhop = 30;
guint cfg_firsthop = 1;
guint cfg_verify = 0;
guint _sport_multiplier;
guint cfg_retrace_range = 3;
gboolean cfg_resolve = FALSE;
gboolean cfg_version = FALSE;
GString* cfg_logfile;
char* _cfg_logfile;
double cfg_waittime = 2.;
double cfg_update_interval = 60.;
double cfg_expire = 86400.;
double cfg_debug = FALSE;

GOptionEntry gopts[] = {
	{"debug", 'd', 0, G_OPTION_ARG_NONE, &cfg_debug, 
		"Enable debug output", NULL},
	{"expire", 0, 0, G_OPTION_ARG_DOUBLE, &cfg_expire, 
		"Hop value expires after N seconds (86400)", "N"},
	{"first", 'f', 0, G_OPTION_ARG_INT, &cfg_firsthop, 
		"Start from the first_ttl hop (1)", "first_ttl"},
	{"log", 'l', 0, G_OPTION_ARG_STRING, &_cfg_logfile, 
		"Log file (~/.tracehop)", "logfile"},
	{"max", 'm', 0, G_OPTION_ARG_INT, &cfg_maxhop, 
		"Max hop (30)", "max_ttl"},
	{"resolve", 'r', 0, G_OPTION_ARG_NONE, &cfg_resolve, 
		"Resolve numeric ip to host name", NULL},
	{"retrace-range", 0, 0, G_OPTION_ARG_INT, &cfg_retrace_range, 
		"Retrace ttls in [oldhop-N, oldhop+N] (3)", "N"},
	{"update", 0, 0, G_OPTION_ARG_DOUBLE, &cfg_update_interval, 
		"Check expiration every N seconds (60)", "N"},
	{"verify", 'y', 0, G_OPTION_ARG_INT, &cfg_verify, 
		"Verify hop value for N times after tracing (0)", "N"},
	{"version", 'V', 0, G_OPTION_ARG_NONE, &cfg_version, 
		"Print version info and exit", NULL},
	{"wait", 0, 0, G_OPTION_ARG_DOUBLE, &cfg_waittime, 
		"Wait response for N seconds (2)", "N"},
	{NULL, 0, 0, 0, NULL, NULL, NULL}
};



gpointer recv_thread(gpointer _){
	g_debug("recv: start");
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if(s == -1){
		g_critical("recv: socket: %s", strerror(errno));
		return _;
	}

#define RCVBUF (LIBNET_IPV4_H + LIBNET_TCP_H)
	char buf[RCVBUF];
	struct libnet_ipv4_hdr* iph;
	struct libnet_tcp_hdr* tcph;
	iph = (struct libnet_ipv4_hdr*)buf;
	tcph = (struct libnet_tcp_hdr*)(buf + LIBNET_IPV4_H);

	guint n;
	for(recv_continue = TRUE; recv_continue; ){
		n = read(s, buf, RCVBUF); 
		if(!recv_continue)break;
		if(n < RCVBUF){
			g_warning("recv: read: %s", 
						errno ? strerror(errno) : "Not enough");
			continue;
		}
		//inbound tcp only
		if(iph->ip_p != IPPROTO_TCP || iph->ip_dst.s_addr != myip)
			continue;

		/* received syn/ack */
		record_t* r;
		if(tcph->th_flags == (TH_SYN|TH_ACK)){
			/* lookup for existing value */
			G_LOCK(ip2hop);
			r = g_hash_table_lookup(ip2hop, (gpointer)iph->ip_src.s_addr);
			G_UNLOCK(ip2hop);

			if(r != NULL && r->hop != 0) // found, send rst
				inject(iph, tcph, r);
			//r->hop == 0 means dest not reachable
		}

		//we'll handle syn/ack and rst/*
		if((tcph->th_flags == (TH_SYN|TH_ACK) && r == NULL)
			|| (tcph->th_flags & TH_RST))
			g_async_queue_push(packet_queue, g_slice_copy(RCVBUF, buf));
	}

	close(s);
	
	g_debug("recv: return");
	return _;
}



job_t* job_new(gulong addr, gushort port){
	job_t* j = g_slice_new0(job_t);
	j->daddr = addr;
	j->dport = port;
	j->lrt = 256;
//	j->sport = g_rand_int_range(rnd, 1024, 65536);
//	j->seq = g_rand_int_range(rnd, -0x80000000, 0x7fffff00) + 0x80000000;
//	j->id = g_rand_int_range(rnd, 0, 65536);
	j->name = g_string_new(addr2name(addr));
	j->timer = g_timer_new();
	j->sent = FALSE;
	j->traced = FALSE;
	j->reply = 0;
	g_debug("new job: %s:%hu", j->name->str, j->dport);
	return j;
}

void job_free(gpointer p){
	job_t* j = p;
	g_string_free(j->name, TRUE);
	g_timer_destroy(j->timer);
	g_slice_free(job_t, j);
}



record_t* record_new(job_t* j){
	record_t* r = g_slice_new0(record_t);
	r->hop = j->lrt;
	r->addr = j->daddr;
	r->port = j->dport;
	r->name = g_string_new(j->name->str);
	r->time = time(NULL);
	return r;
}

void record_free(gpointer p){
	g_string_free(((record_t*)p)->name, TRUE);
	g_slice_free(record_t, p);
}

void packet_free(gpointer p){
	g_slice_free1(RCVBUF, p);
}



char* addr2name(guint _addr){
	static char name[NI_MAXHOST];
	name[0] = 0;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = _addr;
	if(cfg_resolve){
		getnameinfo((struct sockaddr*)&addr, sizeof(addr), name, 
								NI_MAXHOST, NULL, 0, 0);
	}else{
		inet_ntop(AF_INET, (struct in_addr*)&_addr, name, NI_MAXHOST);
	}
	return name;
}

void print_packet(struct libnet_ipv4_hdr* iph, struct libnet_tcp_hdr* tcph){
	gboolean first = TRUE;
#define PRINTFLAG(f) \
if(tcph->th_flags & TH_##f){\
	if(!first)fputc(' ', stderr);\
	fprintf(stderr,#f);\
	first=FALSE;\
}
	PRINTFLAG(FIN)
	PRINTFLAG(SYN)
	PRINTFLAG(RST)
	PRINTFLAG(PUSH)
	PRINTFLAG(ACK)
	PRINTFLAG(URG)
	PRINTFLAG(ECE)
	PRINTFLAG(CWR)
	fprintf(stderr, " from %s:%hu (id=%04x ttl=%hhu seq=%08x)\n", 
					addr2name(iph->ip_src.s_addr), 
					ntohs(tcph->th_sport),
					ntohs(iph->ip_id),
					iph->ip_ttl,
					ntohl(tcph->th_seq));
}



void inject(struct libnet_ipv4_hdr* iph, 
						struct libnet_tcp_hdr* tcph, record_t* r){


	static libnet_t* l = NULL;
	static char errbuf[LIBNET_ERRBUF_SIZE];
	static libnet_ptag_t tcp = 0;
	static libnet_ptag_t ip = 0;

	if(l == NULL){
		l = libnet_init(LIBNET_RAW4, NULL, errbuf);
		if(l == NULL)
			g_error("libnet_init: %s", errbuf);
		return;
	}
	if(r == NULL)
		return;

	tcp = libnet_build_tcp(ntohs(tcph->th_dport), ntohs(tcph->th_sport),
										ntohl(tcph->th_ack), ntohl(tcph->th_seq)+1, TH_RST|TH_ACK, 
										0, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);

	ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, tcph->th_seq, 
												IP_DF, r->hop-1, IPPROTO_TCP, 0, myip, 
												iph->ip_src.s_addr, NULL, 0, l, ip);
	
	if(-1 == libnet_write(l))
		g_warning("inject: libnet_write: %s", libnet_geterror(l));

	g_debug("inject: rst to %s, ttl=%hhu", r->name->str, r->hop-1);
}


void trace(job_t* j){
	//when j->traced == TRUE, this is a verification and j->lrt > 0
	//when j->traced == FALSE, this is the initial trace

	g_debug(j->traced?"verify: %s":"trace: %s", j->name->str);

	int start, end;

	j->sport = g_rand_int_range(rnd, 1024, 65536);
	j->seq = g_rand_int_range(rnd, -0x80000000, 0x7fffffff);
	j->id = g_rand_int_range(rnd, 0, 65536);

	if(j->traced){
		start = 1;
		end = cfg_verify;
	}else{
		record_t*	r = g_hash_table_lookup(ip2hop, (gpointer)j->daddr);
		if(r == NULL || r->hop == 0){
			/* not traced or traced but unreachable */
			start = cfg_firsthop;
			end = cfg_maxhop;
		}else{
			/* retracing existing reachable host */
			start = r->hop - cfg_retrace_range;
			end = r->hop + cfg_retrace_range;
		}
	}
	start = MAX(0, start);
	end = MIN(255, end);

	/* Each TCP ACK ping with FIN to specifically avoid gfw noise,
	expecting a RST reply with specified SEQ. */

	int i;
	for(i = start; i <= end; i++){
		guint ttl = j->traced ? j->lrt - 1 : (guint)i;
		guint k = i*_sport_multiplier;

		tcp = libnet_build_tcp(j->sport + k, j->dport, 0, j->seq + k,
								TH_ACK|TH_FIN, 0, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);

		ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, j->id + i, 
							IP_DF, ttl, IPPROTO_TCP, 0, myip, j->daddr, NULL, 0, l, ip);

		if(-1 == libnet_write(l))
			g_warning("trace: libnet_write: %s", libnet_geterror(l));
	}

	g_timer_start(j->timer);
}


/* sync ip2hop hash table between memory and disk */
void logsync(gboolean shutdown){
	guint size = g_hash_table_size(ip2hop);
	if(size || shutdown){
	//from memory to disk
		g_message("logsync: saving as %s", cfg_logfile->str);
		FILE* log = fopen(cfg_logfile->str, "w");
		if(log == NULL){
			g_warning("logsync: %s", strerror(errno));
			return;
		}

		GHashTableIter it;
		record_t* r;

		g_hash_table_iter_init(&it, ip2hop);
		while(g_hash_table_iter_next(&it, NULL, (gpointer)&r))
			fprintf(log, "%s %08x %04x %u %08x\n", 
									r->name->str, r->addr, r->port, r->hop, r->time);

		fclose(log);
	}else{//from disk to memory
		g_message("logsync: loading %s", cfg_logfile->str);
		char name[1024]="";
		FILE* log = fopen(cfg_logfile->str, "r");
		if(log == NULL){
			g_message("logsync: %s", strerror(errno));
			return;
		}

		record_t t;
		t.time = 0;
		while(5 == fscanf(log, "%s %08x %04hx %hhd %08x\n", 
												name, &t.addr, &t.port, &t.hop, &t.time)){
			record_t* r = g_slice_dup(record_t, &t);
			r->name = g_string_new(name);
			g_hash_table_replace(ip2hop, (gpointer)r->addr, r);
		}

		fclose(log);
	}
}



void cleanup(){
	g_debug("cleaning up");

	recv_continue = FALSE;
	/* read() blocks,
	 so in an easy way send a packet to make it return, */
	libnet_build_tcp(1, 1, 0, 0, 0, 0, 0, 0, LIBNET_TCP_H, NULL, 0, l, tcp);
	libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 0, 0, 1, IPPROTO_TCP, 
										0, myip, myip, NULL, 0, l, ip);
	if(-1 == libnet_write(l))
		g_warning("cleanup: libnet_write: %s", libnet_geterror(l));
	g_thread_join(recvt);

	/* free everything */
	g_rand_free(rnd);
	g_timer_destroy(update);
	g_async_queue_unref(packet_queue);
	for(; jobs->head; g_queue_pop_head_link(jobs))
		job_free(jobs->head->data);
	g_queue_free(jobs);
	g_hash_table_destroy(ip2hop);

	libnet_destroy(l);

	g_string_free(cfg_logfile, TRUE);
}


void quiet(const gchar* a, GLogLevelFlags b, const gchar* c, gpointer d){
	(void)a; (void)b; (void)c; (void)d;
}

void init(int argc, char** argv){
	g_thread_init(NULL);

	/* options */
	GOptionContext* context = g_option_context_new(NULL);
	//g_option_context_set_summary(context, _DESCR);
	g_option_context_add_main_entries(context, gopts, NULL);
	if(!g_option_context_parse(context, &argc, &argv, &gerr))
		g_error("g_option_context_parse: %s", gerr->message);
	g_option_context_free(context);

	if(cfg_version){
		fprintf(stderr, "%s - %s\nVersion %s, %s\n%s\n",
						_NAME, _DESCR, _VERSION, _DATE, _COPYING);
		exit(0);
	}
	
	_sport_multiplier = 65536/cfg_verify;

	if(cfg_firsthop > cfg_maxhop){
		fprintf(stderr, "firsthop must be less than maxhop\n");
		exit(1);
	}

	if(!cfg_debug)
		g_log_set_handler(NULL, G_LOG_LEVEL_DEBUG | G_LOG_FLAG_FATAL
						| G_LOG_FLAG_RECURSION, quiet, NULL);
	if(_cfg_logfile){
		cfg_logfile = g_string_new(_cfg_logfile);
	}else{
		cfg_logfile = g_string_new(getenv("HOME"));
		g_string_append(cfg_logfile, "/.tracehop");
	}

	/* init libnet */
	l = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if(l == NULL)
		g_error("libnet_init: %s", errbuf);
	inject(NULL, NULL, NULL);

	/* new everything */
	myip = libnet_get_ipaddr4(l);
	ip2hop = g_hash_table_new_full(g_direct_hash, g_direct_equal, 
																NULL, record_free);
	jobs = g_queue_new();
	packet_queue = g_async_queue_new_full(packet_free);
	update = g_timer_new();
	rnd = g_rand_new();

	/* install signal handler */
	signal(SIGINT, sigh);
	signal(SIGQUIT, sigh);
	signal(SIGTERM, sigh);

}



void sigh(int _){
	(void)_;
	main_continue = FALSE;
}

gint _cmp(gconstpointer a, gconstpointer b){
	const job_t* j = a;
	return j->daddr - (gulong)b;
}

int main(int argc, char** argv){
	/* init */
	init(argc, argv);

	/* sync log */
	logsync(FALSE);

	/* start listening thread */
	recvt = g_thread_create(recv_thread, NULL, TRUE, &gerr);
	if(NULL == recvt)
		g_error("g_thread_create: %s", gerr->message);


	/* main loop */
	for(main_continue = TRUE; main_continue; g_usleep(100)){
		char* buf;
		GList* p;
		job_t* j;

		/* receive async packet */
		while((buf = g_async_queue_try_pop(packet_queue))){
			struct libnet_ipv4_hdr* iph;
			struct libnet_tcp_hdr* tcph;
			iph = (struct libnet_ipv4_hdr*)buf;
			tcph = (struct libnet_tcp_hdr*)(buf + LIBNET_IPV4_H);

			/* should be new job on syn/ack */
			if(tcph->th_flags == (TH_SYN|TH_ACK)){
				if(NULL == 
				g_queue_find_custom(jobs, (gpointer)iph->ip_src.s_addr, _cmp)){
					job_t* t = job_new(iph->ip_src.s_addr, ntohs(tcph->th_sport));
					g_queue_push_tail(jobs, t);
				}else{
					g_debug("job exists: %s", addr2name(iph->ip_src.s_addr));
				}
			}

			/* received rst */
			if(tcph->th_flags & TH_RST){
				gboolean is_reply = FALSE;

				for(p = jobs->head; p != NULL; p = p->next){
					j = p->data;
					gulong seq_offset = ntohl(tcph->th_seq) - j->seq;
					gushort port_offset = ntohs(tcph->th_dport) - j->sport;
					guint ttl = j->traced?j->lrt-!j->reply:seq_offset/_sport_multiplier;
					if(iph->ip_src.s_addr == j->daddr
						&& ntohs(tcph->th_sport) == j->dport 
						&& port_offset == seq_offset
						&& seq_offset%_sport_multiplier == 0
						/* without loss of generality, 
						the next line is commented */
						//&& ttl >= 1	&& ttl <= cfg_maxhop
						&& (tcph->th_flags & TH_RST)){
						/* is reply of the tcp fin/ack ping */
						g_debug("reply from %s, ttl %u/%u", 
								j->name->str, ttl, j->lrt);
						j->reply++;
						if(ttl < j->lrt) 
							j->lrt = ttl;
						is_reply = TRUE;
						break;
					}
				}
				
				if(!is_reply) {
					/* non-reply rst, forged? 
					print it as a warning*/
					print_packet(iph, tcph);
				}
			}
			packet_free(buf);
		} /* while((buf = g_async_queue_try_pop(packet_queue))) */

		/* process new and timeout jobs */
		for(p = jobs->head; p != NULL; p = p->next){
			j = p->data;

			if(!j->sent){
				/* trace stage: what's the least reaching ttl(LRT)? */
				
				//j->sent == FALSE
				//j->traced == FALSE
				//j->reply == 0
				//j->lrt == 256
				trace(j);
				j->sent = TRUE;
			}

			if(g_timer_elapsed(j->timer, NULL) > cfg_waittime){
				/* this job timed out */

				if(j->lrt > cfg_maxhop)
					j->lrt = 0;
				j->traced = TRUE;

				g_message("%s has hop %u%s", 
								j->name->str, j->lrt, j->lrt&&!j->reply?", verified":"");

				if(cfg_verify > 0 && j->reply > 0 && j->lrt > 1){
					/* verification stage: is the LRT stable? */

					j->reply = 0;
					/* now trace() will send ACK pings with ttl == lrt-1 */

					//j->sent == TRUE
					//j->traced == TRUE
					//j->reply == 0
					//j->lrt > 0
					trace(j);
					continue;
					/* job continues */
				}

				/* j->reply == 0 may mean:
				1) host is unreachable, i.e. j->lrt == 0;
				2) verifying ACK pings have no reply, i.e. verified.
				Both condition terminate the job. */

				record_t* r = record_new(j);

				G_LOCK(ip2hop);
				g_hash_table_replace(ip2hop, (gpointer)j->daddr, r);
				G_UNLOCK(ip2hop);
				g_debug("%s,%u saved", j->name->str, j->lrt);

				job_free(j);

				GList next = {NULL, NULL, NULL};
				next.next = p->next;
				g_queue_delete_link(jobs, p);
				p = &next;
			}
		}

		/* check ip2hop table for update */
		if(g_timer_elapsed(update, NULL) > cfg_update_interval){
			g_debug("check ip2hop table for update");

			logsync(FALSE);

			GHashTableIter it;
			record_t* r;

			g_hash_table_iter_init(&it, ip2hop);
			while(g_hash_table_iter_next(&it, NULL, (gpointer)&r)){
				GTimeVal time;

				g_get_current_time(&time);
				if(time.tv_sec - r->time > cfg_expire)
					g_queue_push_tail(jobs, job_new(r->addr, r->port));
			}

			g_timer_start(update);
		}


	}

	logsync(TRUE);
	cleanup();
	return 0;
}
