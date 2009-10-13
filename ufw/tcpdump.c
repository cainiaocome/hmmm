#include <stdio.h>
#include "packet.h"
#include "tcpdump.h"


void savedump(char* file, packet* head){
	(void)file; (void)head;
	fprintf(stderr, "** savedump() not implemented.\n");
}

packet* loaddump(char* file){
	(void)file;
	fprintf(stderr, "** loaddump() not implemented.\n");
	return NULL;
}
