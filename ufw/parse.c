#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/tcp.h>
#define TH_ECE 0x40
#define TH_CWR 0x80
#include <netinet/ip.h>
#include <ctype.h>
#include "net.h"
#include "log.h"

#define PARSE(format, ...)\
	if(debug >= 2){\
		fprintf(stderr, "-P %s:%d: " format " >", __FILE__, __LINE__, \
				##__VA_ARGS__);\
		fwrite(line+pos, 1, n-pos, stderr);\
		fputc('\n', stderr);\
	}

#ifndef _PARSE_STANDALONE
extern int mtu;
extern int udp_mode;
extern tcp_seq seq, ack, isn, ian;
extern int ttl;
#else
int verbose = 10;
int debug = 2;
int mtu = 1500;
int udp_mode = 0;
tcp_seq seq, ack, isn, ian;
int ttl = 255;
#endif

static int inset(char* delim, char c){
	while(*delim && c != *delim)delim++;
	return *delim;
}
#define max(a, b) ((a) > (b) ? (a) : (b))

#define tok_repeat 'x'
#define tok_sleep '*'
#define tok_usleep '/'
#define tok_hdrdelim ';'
#define tok_tcpdelim ','
#define tok_gotopayload ':'
#define tok_tcpemptyflag '_'
#define tok_tcptmpplus ']'
#define tok_tcptmpminus '['
#define tok_tcppreplus '+'
#define tok_tcppreminus '-'
#define tok_tcppostplus '+'
#define tok_tcppostminus '-'
#define tok_tcpabs '~'
#define tok_payload_esc '\\'
#define tok_payload_file 'f'
#define tok_payload_exec 'e'
#define toks_ctl "x*/"
#define toks_ip "0123456789"
#define toks_tcp "FSRPAUECfsrpauec_"
#define delim_space " \f\n\r\t\v"
#define delim_hdr ";"
#define delim_tcp ","
#define delim2_tcp "."

#define skipspace() while(isspace(line[pos])&&pos<n)pos++
#define nextdelim(delim) while(!inset(delim, line[pos]) && pos < n)pos++
#define hastoken(tokens) inset(tokens, line[pos])

void interpret(char* line, size_t n){
	if(!line)
		return;
	if(!n)
		return;
	size_t pos = 0;
	skipspace();
	if(line[pos] == '#' && pos == 0)
		return;

	static enum {CTL, IP, TCP, PAYLOAD} state = CTL;
	enum {FLAGS, SEQ, ACK} tcp_state = FLAGS;
	int v, vlen;
	char tok;

	int _ttl = ttl;
	int _flags = 0;
	tcp_seq _seq = seq;
	tcp_seq _ack = ack;
	char payload[IP_MAXPACKET];
	size_t payload_s = 0;

	while(pos < n){
		skipspace();
		tok = line[pos];
		PARSE("token: %c(%#02x)", tok, tok);
		if(state == CTL){
			if(tok == tok_repeat){
				pos++;
				skipspace();
				sscanf(line + pos, "%u%n", &v, &vlen);
				pos += vlen;
				PARSE("repeat: %d", v);
				for(v--; v > 0; v--){
					interpret(line + pos, n - pos);
					state = CTL;
				}
			}else if(tok == tok_sleep){
				pos++;
				skipspace();
				sscanf(line + pos, "%u%n", &v, &vlen);
				pos += vlen;
				PARSE("sleep: %d", v);
				sleep(v);//send_delay += v*1000000;
				_seq = seq; _ack = ack;
			}else if(tok == tok_usleep){
				pos++;
				skipspace();
				sscanf(line + pos, "%u%n", &v, &vlen);
				pos += vlen;
				PARSE("usleep: %d", v);
				usleep(v);//send_delay += v;
				_seq = seq; _ack = ack;
			}else if(tok == tok_hdrdelim){
				pos++;
				state = IP;
				PARSE("state -> IP");
			}else if(tok == tok_gotopayload && udp_mode){
				pos++;
				state = PAYLOAD;
				PARSE("state -> PAYLOAD");
			}else if(inset(toks_ip, tok)){
				state = IP;
				PARSE("state -> IP");
			}else if(inset(toks_tcp, tok)){
				state = TCP;
				PARSE("state -> TCP");
			}else{
				pos++;
				PARSE("illegal token: %c", tok);
				MESSAGE("bad syntax");
				goto stop_parse;
			}
		}else if(state == IP){
			if(inset(toks_ip, tok)){
				sscanf(line + pos, "%u%n", &v, &vlen);
				pos += vlen;
				_ttl = v;
				PARSE("ttl: %d", v);
			}else if(tok == tok_hdrdelim){
				pos++;
				state = TCP;
				PARSE("state -> TCP");
			}else if(tok == tok_gotopayload && udp_mode){
				pos++;
				state = PAYLOAD;
				PARSE("state -> PAYLOAD");
			}else if(inset(toks_tcp, tok)){
				state = TCP;
				PARSE("state -> TCP");
			}else{
				pos++;
				PARSE("illegal token: %c", tok);
				MESSAGE("bad syntax");
				goto stop_parse;
			}
		}else if(state == TCP){
			if(tcp_state == FLAGS){
				tok = toupper(tok);
				pos++;
				if(tok == 'F')
					_flags |= TH_FIN;
				else if(tok == 'S')
					_flags |= TH_SYN;
				else if(tok == 'R')
					_flags |= TH_RST;
				else if(tok == 'P')
					_flags |= TH_PUSH;
				else if(tok == 'A')
					_flags |= TH_ACK;
				else if(tok == 'U')
					_flags |= TH_URG;
				else if(tok == 'E')
					_flags |= TH_ECE;
				else if(tok == 'C')
					_flags |= TH_CWR;
				else if(tok == tok_tcpemptyflag)
					_flags |= 0;
				else if(tok == tok_tcpdelim){
					tcp_state = SEQ;
					PARSE("tcp-state -> SEQ");
				}else if(tok == tok_gotopayload || tok == tok_hdrdelim){
					state = PAYLOAD;
					PARSE("state -> PAYLOAD");
				}else {
					PARSE("illegal token: %c", tok);
					MESSAGE("bad syntax");
					goto stop_parse;
				}
			}else if(tcp_state == SEQ || tcp_state == ACK){
				char* NAME = tcp_state == SEQ ? "SEQ" : "ACK";
				char* name = tcp_state == SEQ ? "seq" : "ack";
				tcp_seq* num = tcp_state == SEQ ? &seq : &ack;
				tcp_seq* _num = tcp_state == SEQ ? &_seq : &_ack;
				if(tok == tok_tcptmpplus){
					pos++;
					skipspace();
					sscanf(line + pos, "%u%n", &v, &vlen);
					pos += vlen;
					*_num += v;
					PARSE("send %s as %s + %u", name, NAME, v);
				}else if(tok == tok_tcptmpminus){
					pos++;
					skipspace();
					sscanf(line + pos, "%u%n", &v, &vlen);
					pos += vlen;
					*_num -= v;
					PARSE("send %s as %s - %u", name, NAME, v);
				}else if(tok == tok_tcppreplus){
					pos++;
					skipspace();
					sscanf(line + pos, "%u%n", &v, &vlen);
					pos += vlen;
					*num += v;
					*_num = *num;
					PARSE("%s += %d, and send %s as %s", NAME, v, name, NAME);
				}else if(tok == tok_tcppreminus){
					pos++;
					skipspace();
					sscanf(line + pos, "%u%n", &v, &vlen);
					pos += vlen;
					*num -= v;
					*_num = *num;
					PARSE("%s -= %d, and send %s as %s", NAME, v, name, NAME);
				}else if(tok == tok_tcpabs){
					pos++;
					skipspace();
					sscanf(line + pos, "%u%n", &v, &vlen);
					pos += vlen;
					*_num = v;
					PARSE("send %s as the initial %s + %u", name, NAME, v);
				}else if(isdigit(tok)){
					sscanf(line + pos, "%u%n", &v, &vlen);
					pos += vlen;
					*_num = v;
					int has_postfix = 0;
					if(pos < n){
						tok = line[pos];
						if(tok == tok_tcppostplus){
							pos++;
							*_num = *num;
							*num += v;
							has_postfix = 1;
							PARSE("send %s as %s, and %s += %u", name, NAME, NAME, v);
						}else if(tok == tok_tcppostminus){
							pos++;
							*_num = *num;
							*num -= v;
							has_postfix = 1;
							PARSE("send %s as %s, and %s += %u", name, NAME, NAME, v);
						}
					}
					if(!has_postfix)
						PARSE("send %s as %u", name, v);
				}else if(tok == tok_tcpdelim && tcp_state == SEQ){
					pos++;
					tcp_state = ACK;
					PARSE("tcp-state -> ACK");
				}else if(tok == tok_tcpdelim && tcp_state == ACK){
					pos++;
					state = PAYLOAD;
					PARSE("state -> PAYLOAD");
				}else if(tok == tok_hdrdelim || tok == tok_gotopayload){
					pos++;
					state = PAYLOAD;
					PARSE("state -> PAYLOAD");
				}else{
					pos++;
					PARSE("illegal token: %c", tok);
					MESSAGE("bad syntax");
					goto stop_parse;
				}
			}
		}else while(state == PAYLOAD && pos < n){
			tok = line[pos];
			if(tok == tok_payload_esc && pos+1 < n){
				pos++;
				tok = line[pos];
				if(tok == tok_payload_file){
					pos++;
					FILE* f = fopen(line + pos, "r");
					if(f == NULL){
						ERROR(line + pos);
					}else{
						payload_s = fread(payload, 1, mtu, f);
						fclose(f);
					}
					pos = n;
					PARSE("open file: %s", line + pos);
				}else if(line[pos+1] == tok_payload_exec){
					pos++;
					FILE* f = popen(line + pos, "r");
					if(f == NULL){
						ERROR(line + pos);
					}else{
						payload_s = fread(payload, 1, mtu, f);
						fclose(f);
					}
					pos = n;
					PARSE("execute: %s", line + pos);
				}else if(line[pos] == 'n'){
					pos++;
					payload[payload_s++] = '\n';
				}else if(line[pos] == 'r'){
					pos++;
					payload[payload_s++] = '\r';
				}else if(line[pos] == '\\'){
					pos++;
					payload[payload_s++] = '\\';
				}else{
					payload[payload_s++] = '\\';
				}
			}else{
				payload[payload_s++] = line[pos++];
			}
		}
	}
	PARSE("FIN. ttl:%u flags:%02x seq:%u ack:%u payload_size:%u",
		_ttl, _flags, _seq - isn, _ack - ian, payload_s);

#ifndef _PARSE_STANDALONE
		net_send(_ttl, _flags, _seq, _ack, payload, payload_s);
#endif
stop_parse:
	state = CTL;
}
