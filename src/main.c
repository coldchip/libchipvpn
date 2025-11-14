#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "util.h"
#include "log.h"
#include "config.h"
#include "chipvpn.h"

#include <arpa/inet.h>


volatile sig_atomic_t quit = 0;

void terminate(int type) {
	chipvpn_log_append("interrupt received\n");
	quit = 1;
}

int chipvpn_auth_main(int argc, char const *argv[], int rfd, int wfd) {
	signal(SIGPIPE, SIG_IGN);

	char *file = chipvpn_read_file(argv[1]);
	if(!file) {
		chipvpn_log_append("unable to open config %s\n", argv[1]);
		exit(1);
	}

	write(wfd, file, strlen(file));

	free(file);

	while(1) {
		sleep(1);		
	}

	return 0;
}

int chipvpn_main(int argc, char const *argv[], int rfd, int wfd) {
	srand(time(NULL));

	chipvpn_log_append("chipvpn %i alpha protocol %i\n", CHIPVPN_VERSION, CHIPVPN_PROTOCOL_VERSION); 

	if(!(argc > 1 && argv[1] != NULL)) {
		chipvpn_log_append("config path required\n");
		exit(1);
	}

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);

	chipvpn_t *vpn = chipvpn_create(-1, rfd, wfd);
	if(!vpn) {
		chipvpn_log_append("unable to create vpn tunnel interface\n");
		exit(1);
	}

	while(!quit) {
		chipvpn_poll(vpn, 250);
		chipvpn_service(vpn);
	}

	chipvpn_log_append("cleanup\n");

	chipvpn_cleanup(vpn);

	chipvpn_log_append("shutting down\n"); 

	return 0;
}

int main(int argc, char const *argv[]) {
	int sv[2];

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
		exit(1);
	}

	int auth_fd = sv[0];
	int vpn_fd  = sv[1];

	// ******************************

	pid_t p = fork();
	if(p < 0) {
		printf("fork fail");
		exit(1);
	} else if(p == 0) {
		int ret = chipvpn_auth_main(argc, argv, auth_fd, auth_fd);

		close(auth_fd);
		close(vpn_fd);

		exit(ret);
	} else {
		int ret = chipvpn_main(argc, argv, vpn_fd, vpn_fd);

		kill(p, SIGTERM);
		waitpid(p, NULL, 0);

		close(auth_fd);
		close(vpn_fd);

		exit(ret);
	}
	return 0;
}