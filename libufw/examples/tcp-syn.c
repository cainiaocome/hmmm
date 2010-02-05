#include "ufwutil.h"

int main(){
	ufw_sk *sk;
	u_int32_t dest = ufw_atoh("66.249.89.99");

	sk = ufw_socket(TCP, PRINT_ALL|FATAL|FILTER_CONN|DUMP_ALL|DUMP_AUTONAME);

	ufw_connect(sk, dest, 80);

	ufw_send_tcp(sk, SYN, 123, 0, 0, 0);

	ufw_pause(sk);

	ufw_close(sk);

	return 0;
}
