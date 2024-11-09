#include <stdio.h>
#include "auth.h"

void chipvpn_auth_enqueue(char *key) {
	printf("auth attempt\n");

	for(int i = 0; i < 32; ++i) {
		printf("%02x", key[i] & 0xff);
	}
	printf("\n");
}