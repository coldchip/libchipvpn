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

static volatile sig_atomic_t quit = 0;

static void terminate(int type) {
	(void)type;
	quit = 1;
}

/*
 * Child process: read the config file and stream it (NUL-terminated) to
 * the parent over the socketpair, then idle until the parent tears us down.
 */
int chipvpn_auth_main(int argc, char const *argv[], int fd) {
	(void)argc;

	signal(SIGPIPE, SIG_IGN);

	char *file = chipvpn_read_file(argv[1]);
	if(!file) {
		chipvpn_log_append("unable to open config %s\n", argv[1]);
		exit(1);
	}

	if(write(fd, file, strlen(file) + 1) < 0) {
		chipvpn_log_append("unable to send config to vpn process\n");
	}

	free(file);

	while(1) {
		sleep(1);
	}

	return 0;
}

/*
 * Parent process: run the VPN engine's poll/service loop until a signal
 * requests shutdown.
 */
int chipvpn_main(int argc, char const *argv[], int fd) {
	(void)argc;
	(void)argv;

	srand(time(NULL));

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);

	chipvpn_t *vpn = chipvpn_create(-1, -1, fd);
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
	chipvpn_log_append("chipvpn v%i protocol %i\n", CHIPVPN_VERSION, CHIPVPN_PROTOCOL_VERSION);

	if(!(argc > 1 && argv[1] != NULL)) {
		chipvpn_log_append("config path required\n");
		exit(1);
	}

	int sv[2];
	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
		exit(1);
	}

	int auth_fd = sv[0];
	int vpn_fd  = sv[1];

	pid_t pid = fork();
	if(pid < 0) {
		perror("fork");
		exit(1);
	} else if(pid == 0) {
		/* child: config reader */
		int ret = chipvpn_auth_main(argc, argv, auth_fd);

		close(auth_fd);
		close(vpn_fd);

		exit(ret);
	} else {
		/* parent: vpn engine */
		int ret = chipvpn_main(argc, argv, vpn_fd);

		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);

		close(auth_fd);
		close(vpn_fd);

		exit(ret);
	}

	return 0;
}
