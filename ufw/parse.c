#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#define TH_ECE 0x40
#define TH_CWR 0x80
#include <netinet/ip.h>
#include <ctype.h>
#include "net.h"
#include "log.h"

#define PARSE(format, ...)\
	if(debug >= 1){\
		fprintf(stderr, "-P %s:%d: " format ">", __FILE__, __LINE__, \
				##__VA_ARGS__);\
		fwrite(line+pos, 1, n-pos, stderr);\
		fputc('\n', stderr);\
	}


extern int mtu;
extern int udp_mode;
extern tcp_seq seq, ack, isn, ian;
extern int ttl;
extern int send_delay;

static int isdelim(char* delim, char c){
	while(*delim && c != *delim)delim++;
	return *delim;
}
#define max(a, b) ((a) > (b) ? (a) : (b))

#define tok_repeat 'x'
#define tok_sleep '.'
#define tok_usleep ','
#define tok_hdrdelim ';'
#define tok_tcpdelim ','
#define tok_tcpdelim2 '.'
#define tok_tcpplus '+'
#define tok_tcpminus '-'
#define tok_tcpabs '~'
#define tol_eof 0
#define tok_payload_esc '\\'
#define tok_payload_file 'f'
#define tok_payload_exec 'e'
#define toks_ctl "x*."
#define toks_ip "0123456789"
#define toks_tcp "FSRPAUECfsrpauec"
#define delim_space " \f\n\r\t\v"
#define delim_hdr ";"
#define delim_tcp ","
#define delim2_tcp "."

#define skipspace() while(isspace(line[pos])&&pos<n)pos++
#define nextdelim(delim) while(!isdelim(delim, line[pos]) && pos < n)pos++
#define hastoken(tokens) isdelim(tokens, line[pos])

void interpret(char* line, size_t n){
	if(!line)
		return;
	if(!n)
		return;
	size_t pos = 0;
	skipspace();
	if(line[pos] == '#' && pos == 0)
		return;

	static enum {NONE, CTL, IP, TCP, UDP} state = NONE;
	int t;
	char tok;

	int _ttl = ttl;
	int _flags = 0;
	u_long _seq = seq;
	u_long _ack = ack;
	char payload[IP_MAXPACKET];
	size_t payload_s = 0;

	if(state == NONE && pos < n){
		skipspace();
		if(hastoken(toks_ctl)){
			state = CTL;
			PARSE("state: CTL");
		}else if(hastoken(toks_ip)){
			state = IP;
			PARSE("state: IP");
		}else if(hastoken(toks_tcp) && !udp_mode){
			state = TCP;
			PARSE("state: TCP");
		}else if(udp_mode){
			state = UDP;
			PARSE("state: UDP");
		}else {
			state = CTL;
			PARSE("state: CTL");
		}
	}
	if(state == CTL)
		PARSE("state: CTL");
	while(state == CTL && pos < n){
		skipspace();
		tok = line[pos];
		PARSE("token: %c(%#02x)", tok, tok);

		if(tok == tok_repeat){
			pos++;
			skipspace();
			t = max(atof(line + pos), 0.);
			PARSE("repeat: %d", t);
			nextdelim(delim_space delim_hdr);
			for(t--;t>0;t--){
				interpret(line + pos, n - pos);
				state = CTL;
			}
		}else if(tok == tok_sleep){
			pos++;
			skipspace();
			send_delay += 1e6*max(atof(line + pos), 0.);
			PARSE("sleep: %.0f", max(atof(line + pos), 0.));
			nextdelim(delim_space delim_hdr);
		}else if(tok == tok_usleep){
			pos++;
			skipspace();
			send_delay += max(atof(line + pos), 0.);
			PARSE("usleep: %.0f", max(atof(line + pos), 0.));
			nextdelim(delim_space delim_hdr);
		}else if(tok == tok_hdrdelim){
			pos++;
			state = IP;
			PARSE("delim. state: IP");
		}else{ //illegal token
			PARSE("illegal token: %c(%#02x)", tok, tok);
			pos++;
		}
	}
	if(state == IP)
		PARSE("state: IP");
	if(state == IP && pos < n){
		skipspace();
		if(hastoken(toks_ip)){
			state = IP;
			PARSE("state: IP");
		}else if(hastoken(toks_tcp) && !udp_mode){
			state = TCP;
			PARSE("state: TCP");
		}else if(udp_mode){
			state = UDP;
			PARSE("state: UDP");
		}else {
			state = IP;
			PARSE("state: IP");
		}
	}
	if(state == IP)
		PARSE("state: IP");
	while(state == IP && pos < n){
		skipspace();
		tok = line[pos];
		PARSE("token: %c(%#02x)", tok, tok);
		if(isdigit(tok)){
			skipspace();
			t = atoi(line + pos);
			if(t < 0)t = 0;
			if(t > 255)t = 255;
			_ttl = t;
			PARSE("ttl = %d", t);
			nextdelim(delim_space delim_hdr);
		}else if(tok == tok_hdrdelim){
			pos++;
			state = TCP;
			PARSE("delim. state: TCP");
		}else{
			PARSE("illegal token: %c(%#02x)", tok, tok);
			pos++;
		}
	}
	if(state == TCP)
		PARSE("state: TCP");
	if(state == TCP && pos < n){
		skipspace();
		if(hastoken(toks_tcp) && !udp_mode){
			state = TCP;
			PARSE("state: TCP");
		}else if(udp_mode){
			state = UDP;
			PARSE("state: UDP");
		}else {
			state = TCP;
			PARSE("state: TCP");
		}
	}

	enum {FLAGS, SEQ, ACK, PAYLOAD} tcp_state = FLAGS;
	if(state == TCP && tcp_state == FLAGS)
		PARSE("tcp-state: FLAGS");
	if(state == TCP && pos < n){
		while(tcp_state == FLAGS && pos < n){
			skipspace();
			tok = toupper(line[pos]);
			PARSE("token: %c(%#02x)", tok, tok);
			if(tok == 'F'){
				pos++;
				_flags |= TH_FIN;
			}else if(tok == 'S'){
				pos++;
				_flags |= TH_SYN;
			}else if(tok == 'R'){
				pos++;
				_flags |= TH_RST;
			}else if(tok == 'P'){
				pos++;
				_flags |= TH_PUSH;
			}else if(tok == 'A'){
				pos++;
				_flags |= TH_ACK;
			}else if(tok == 'U'){
				pos++;
				_flags |= TH_URG;
			}else if(tok == 'E'){
				pos++;
				_flags |= TH_ECE;
			}else if(tok == 'C'){
				pos++;
				_flags |= TH_CWR;
			}else if(tok == tok_tcpdelim){
				pos++;
				tcp_state = SEQ;
				PARSE("delim. tcp-state: SEQ");
			}else if(tok == tok_tcpdelim2){
				pos++;
				tcp_state = PAYLOAD;
				PARSE("jump. tcp-state: PAYLOAD");
			}else {
				PARSE("illegal token");
				pos++;
			}
		}
		if(tcp_state == SEQ)
			PARSE("tcp-state: SEQ");
		while(tcp_state == SEQ && pos < n){
			skipspace();
			tok = line[pos];
			PARSE("token: %c(%#02x)", tok, tok);
			if(tok == tok_tcpplus){
				pos++;
				skipspace();
				_seq += atoi(line + pos);
				PARSE("_seq = SEQ + %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(tok == tok_tcpminus){
				pos++;
				skipspace();
				_seq -= atoi(line + pos);
				PARSE("_seq = SEQ - %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(tok == tok_tcpabs){
				pos++;
				skipspace();
				_seq = isn + atoi(line + pos);
				PARSE("_seq = ISN + %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(isdigit(tok)){
				_seq = atoi(line + pos);
				PARSE("_seq = %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(tok == tok_tcpdelim){
				PARSE("delim. tcp-state: ACK");
				pos++;
				tcp_state = ACK;
			}else if(tok == tok_tcpdelim2){
				pos++;
				tcp_state = PAYLOAD;
				PARSE("jump. tcp-state: PAYLOAD");
			}else{
				PARSE("illegal token: %c(%#02x)", tok, tok);
				pos++;
			}
		}
		if(tcp_state == ACK)
			PARSE("tcp-state: ACK");
		while(tcp_state == ACK && pos < n){
			skipspace();
			tok = line[pos];
			PARSE("token: %c(%#02x)", tok, tok);
			if(tok == tok_tcpplus){
				pos++;
				skipspace();
				_ack += atoi(line + pos);
				PARSE("_ack = ACK + %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(tok == tok_tcpminus){
				pos++;
				skipspace();
				_ack -= atoi(line + pos);
				PARSE("_ack = ACK - %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(tok == tok_tcpabs){
				pos++;
				skipspace();
				_ack = ian + atoi(line + pos);
				PARSE("_ack = IAN + %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(isdigit(tok)){
				_ack = atoi(line + pos);
				PARSE("_ack = %d", atoi(line + pos));
				nextdelim(delim_space delim_tcp delim2_tcp);
			}else if(tok == tok_tcpdelim){
				pos++;
				tcp_state = PAYLOAD;
				PARSE("delim. tcp-state: PAYLOAD");
			}else{
				pos++;
				PARSE("illegal token: %c(%#02x)", tok, tok);
			}
		}
		if(tcp_state == PAYLOAD)
			PARSE("tcp-state: PAYLOAD");
		while(tcp_state == PAYLOAD && pos < n){
			skipspace();
			tok = line[pos];
			if(tok == tok_payload_esc){
				if(line[pos+1] == tok_payload_file){
					pos += 2;
					skipspace();
					PARSE("open file: %s", line + pos);
					FILE* f = fopen(line + pos, "r");
					if(f == NULL){
						ERROR(line + pos);
					}else{
						payload_s = fread(payload, 1, mtu, f);
						fclose(f);
					}
					break;
				}else if(line[pos+1] == tok_payload_exec){
					pos += 2;
					skipspace();
					PARSE("execute: %s", line + pos);
					FILE* f = popen(line + pos, "r");
					if(f == NULL){
						ERROR(line + pos);
					}else{
						payload_s = fread(payload, 1, mtu, f);
						fclose(f);
					}
					break;
				}else if(line[pos+1] == 'n'){
					pos += 2;
					payload[payload_s++] = '\n';
				}else if(line[pos+1] == 'r'){
					pos += 2;
					payload[payload_s++] = '\r';
				}else if(line[pos+1] == '\\'){
					pos += 2;
					payload[payload_s++] = '\\';
				}else{
					pos++;
					payload[payload_s++] = '\\';
				}
			}else{
				pos++;
				payload[payload_s++] = tok;
			}
		}
	}
	if(state == UDP)
		PARSE("state: UDP");
	while(state == UDP && pos < n){
		skipspace();
		tok = line[pos];
		if(tok == tok_payload_esc){
			if(line[pos+1] == tok_payload_file){
				pos += 2;
				skipspace();
				FILE* f = fopen(line + pos, "r");
				PARSE("open file: %s", line + pos);
				if(f == NULL){
					ERROR(line + pos);
				}else{
					payload_s = fread(payload + payload_s, 1, mtu - payload_s, f);
					fclose(f);
				}
				break;
			}else if(line[pos+1] == tok_payload_exec){
				pos += 2;
				skipspace();
				FILE* f = popen(line + pos, "r");
				PARSE("execute: %s", line + pos);
				if(f == NULL){
					ERROR(line + pos);
				}else{
					payload_s = fread(payload + payload_s, 1, mtu - payload_s, f);
					fclose(f);
				}
				break;
			}else if(line[pos+1] == 'n'){
				pos += 2;
				payload[payload_s++] = '\n';
			}else if(line[pos+1] == 'r'){
				pos += 2;
				payload[payload_s++] = '\r';
			}else if(line[pos+1] == '\\'){
				pos += 2;
				payload[payload_s++] = '\\';
			}else{
				pos++;
				payload[payload_s++] = '\\';
			}
		}else{
			pos++;
			payload[payload_s++] = tok;
		}
	}
	PARSE("parse end.");
	net_send(_ttl, _flags, _seq, _ack, payload, payload_s);
}
