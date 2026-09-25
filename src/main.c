#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "util.h"
#include "log.h"
#include "config.h"
#include "chipvpn.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h> 
#include <errno.h>

volatile sig_atomic_t quit = 0;

void terminate(int type) {
	chipvpn_log_append("interrupt received\n");
	quit = 1;
}

int chipvpn_auth_main(int argc, char const *argv[], int fd) {
	signal(SIGPIPE, SIG_IGN);

	struct stat path_stat;

    if(stat(argv[1], &path_stat) != 0) {
    	chipvpn_log_append("unable to open %s\n", argv[1]);
        return 0;
    }

    if(S_ISREG(path_stat.st_mode)) {
        char *file = chipvpn_read_file(argv[1]);
		if(!file) {
			chipvpn_log_append("unable to open config %s\n", argv[1]);
			return 0;
		}

		write(fd, file, strlen(file) + 1);

		free(file);

		while(1) {
			pause();
		}

        return 0;
    } 
    
    if(S_ISSOCK(path_stat.st_mode)) {
    	while(1) {
	    	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	        if(sock < 0) {
	            chipvpn_log_append("failed to create unix socket\n");
	            return 0;
	        }

	        struct sockaddr_un addr;
	        memset(&addr, 0, sizeof(addr));
	        addr.sun_family = AF_UNIX;
	        strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);

	        while(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	            chipvpn_log_append("retry to connect to unix socket: %s\n", argv[1]);
	            sleep(1);
	        }

	        struct pollfd fds[2];
	        fds[0].fd = sock;
	        fds[0].events = POLLIN;
	        
	        fds[1].fd = fd;
	        fds[1].events = POLLIN;

	        char buf[8192];

	        while (1) {
	            int ret = poll(fds, 2, -1);
	            if(ret < 0) {
	                if(errno == EINTR) continue; 
	                break; 
	            }

	            if(fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
	                ssize_t n = read(sock, buf, sizeof(buf));
	                if(n <= 0) break; 
	                
	                ssize_t written = 0;
	                while(written < n) {
	                    ssize_t w = write(fd, buf + written, n - written);
	                    if (w <= 0) goto proxy_done;
	                    written += w;
	                }
	            }

	            if(fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
	                ssize_t n = read(fd, buf, sizeof(buf));
	                if(n <= 0) break;
	                
	                ssize_t written = 0;
	                while(written < n) {
	                    ssize_t w = write(sock, buf + written, n - written);
	                    if (w <= 0) goto proxy_done;
	                    written += w;
	                }
	            }
	        }

			proxy_done:

	        close(sock);
	        chipvpn_log_append("socket proxy disconnected\n");
        }
    }

	return 0;
}

int chipvpn_main(int argc, char const *argv[], int fd) {
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

	// ******************************

	pid_t p = fork();
	if(p < 0) {
		printf("fork fail");
		exit(1);
	} else if(p == 0) {
		close(vpn_fd);
		
		int ret = chipvpn_auth_main(argc, argv, auth_fd);

		close(auth_fd);

		exit(ret);
	} else {
		close(auth_fd);
		
		int ret = chipvpn_main(argc, argv, vpn_fd);

		kill(p, SIGTERM);
		waitpid(p, NULL, 0);
		
		close(vpn_fd);

		exit(ret);
	}
	return 0;
}