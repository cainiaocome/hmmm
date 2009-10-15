#include <stdio.h>
#include "parse.h"

int main(){
	char linebuf[4096];
	while(fgets(linebuf, 4096, stdin)){
		size_t eol = 0;
		while(linebuf[eol] != '\n' && linebuf[eol] != '\r' && eol < 4096)
			eol++;
		interpret(linebuf, eol);
	}
	return 0;
}
