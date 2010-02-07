#include "ufwutil.h"

int main(){
	u_int32_t dest = ufw_atoh("192.168.0.4");
	u_int32_t source = ufw_atoh("192.168.0.3");
	ufw_sk *sk;
	sk = ufw_socket(TCP, PRINT_RECV|FATAL|FILTER_DPORT);

	//ufw_connect(sk, dest, 80);
	ufw_set_dest(sk, dest, 80);
	ufw_set_source(sk, source, 1234);
	ufw_set_ttl(sk, 3);

	ufw_send_tcp(sk, SYN, 101, 0, 0, 0);
	for(;;)
		ufw_repeat(sk);
	ufw_pause(sk);

	ufw_close(sk);

	return 0;
}
