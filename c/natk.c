#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include <string.h>
#include <stdint.h>
#include <sys/types.h>  
#include <sys/socket.h>  
#include <arpa/inet.h>
#include <netinet/in.h>

int sock() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	while(1) {
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));

		addr.sin_family = AF_INET;
		addr.sin_port = htons(rand() % 65536);
		addr.sin_addr.s_addr = INADDR_ANY;
		if ( bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
			printf("FAILED TO BIND UDP");
			continue;
		}

		break;
	}
	return fd;
}

int main() {
	int s = sock();
	char *msg = "\x00";

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = rand();
	addr.sin_family = AF_INET;
	addr.sin_port = htons(rand() % 65536);

	sendto(s, (const char *)msg, strlen(msg),

        MSG_CONFIRM, (const struct sockaddr *) &addr,

            sizeof(addr));
}
