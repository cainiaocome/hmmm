#include "ufwutil.h"

int main(){
	u_int32_t dest = ufw_atoh("192.168.0.3");
	ufw_sk *sk;
	sk = ufw_socket(TCP, FATAL|FILTER_ADDR);

	ufw_connect(sk, dest, 80);
	ufw_set_ttl(sk, 3);

	ufw_send_tcp(sk, RST, 0, 0, 0, 0);
	for(;;)
		ufw_repeat(sk);

	ufw_close(sk);

	return 0;
}
