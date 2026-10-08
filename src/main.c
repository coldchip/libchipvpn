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
#include <netinet/tcp.h>
#include <sys/un.h>
#include <poll.h> 
#include <errno.h>
#include <fcntl.h>

volatile sig_atomic_t quit = 0;

void terminate(int type) {
	(void)type;

	chipvpn_log_append("interrupt received\n");
	quit = 1;
}

int socket_connect(const char *host, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        chipvpn_log_append("invalid host IP address: %s\n", host);
        return -1;
    }

    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) {
            chipvpn_log_append("failed to create tcp socket: %s\n", strerror(errno));
            sleep(1);
            continue;
        }

        int flags = fcntl(sock, F_GETFL, 0);
        if(flags < 0) flags = 0; 
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        if(res == 0) {
            return sock;
        } 
        
        if(res < 0 && errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = sock, .events = POLLOUT };
            
            if (poll(&pfd, 1, 1000) > 0) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                
                if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0) {
                    return sock;
                }
            }
        }

        close(sock);
        chipvpn_log_append("retry to connect to socket: %s:%u\n", host, port);
        sleep(1); 
    }
}

int chipvpn_auth_main(int argc, char const *argv[], int fd) {
	signal(SIGPIPE, SIG_IGN);

	for(int i = 1; i < argc; i++) {
		const char *path = argv[i];
		if(!path) {
			continue;
		}

		struct stat path_stat;

		if(stat(path, &path_stat) != 0) {
			chipvpn_log_append("file: unable to open %s\n", path);
			continue;
		}

		if(S_ISREG(path_stat.st_mode)) {
			char *file = chipvpn_read_file(path);
			if(!file) {
				chipvpn_log_append("unable to open config %s\n", path);
				continue;
			}

			if(write(fd, file, strlen(file) + 1)) {
				
			}

			free(file);
		}

	}

	for(int i = 1; i < argc; i++) {
		const char *path = argv[i];
		if(!path) {
			continue;
		}

		char ip[100];
		int port = 80;
		if(sscanf(path, "tcp://%99[^:]:%99d", ip, &port) == 2) {
			while(1) {
				int sock = socket_connect(ip, port);
				if(sock < 0) {
					printf("invalid socket");
					continue;
				}

				chipvpn_log_append("connected to: %s\n", path);

				int optval = 1;
				setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

				int idle = 10;     
				int interval = 5; 
				int maxpkt = 3;   

				setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
				setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
				setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(maxpkt));

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
						
						size_t written = 0;
						while(written < (size_t)n) {
							ssize_t w = write(fd, buf + written, (size_t)n - written);
							if (w <= 0) goto proxy_done;
							written += (size_t)w;
						}
					}

					if(fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
						ssize_t n = read(fd, buf, sizeof(buf));
						if(n <= 0) break;
						
						size_t written = 0;
						while(written < (size_t)n) {
							ssize_t w = write(sock, buf + written, (size_t)n - written);
							if (w <= 0) goto proxy_done;
							written += (size_t)w;
						}
					}
				}

				proxy_done:

				close(sock);
				chipvpn_log_append("socket proxy disconnected\n");
			}
		}
	}

	pause();
	
	return 0;
}

int chipvpn_main(int argc, char const *argv[], int fd) {
	srand((unsigned int)time(NULL)); 

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
	chipvpn_log_append("compiled on %s %s\n", __DATE__, __TIME__);

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