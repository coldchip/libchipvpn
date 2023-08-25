#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "peer.h"
#include "chipvpn.h"

bool chipvpn_get_gateway(struct in_addr *gateway, char *dev) {
	int     received_bytes = 0, msg_len = 0, route_attribute_len = 0;
	int     sock = -1, msgseq = 0;
	struct  nlmsghdr *nlh, *nlmsg;
	struct  rtmsg *route_entry;
	// This struct contain route attributes (route type)
	struct  rtattr *route_attribute;
	char    msgbuf[4096], buffer[4096];
	char    *ptr = buffer;
	struct  timeval tv;

	if((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		return false;
	}

	memset(msgbuf, 0, sizeof(msgbuf));
	memset(buffer, 0, sizeof(buffer));

	/* point the header and the msg structure pointers into the buffer */
	nlmsg = (struct nlmsghdr*)msgbuf;

	/* Fill in the nlmsg header*/
	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlmsg->nlmsg_seq = msgseq++; // Sequence of the message packet.
	nlmsg->nlmsg_pid = getpid(); // PID of process sending the request.

	/* 1 Sec Timeout to avoid stall */
	tv.tv_sec = 1;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval*)&tv, sizeof(struct timeval));
	/* send msg */
	if(send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		close(sock);
		return false;
	}

	/* receive response */
	do {
		received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
		if(received_bytes < 0) {
			close(sock);
			return false;
		}

		nlh = (struct nlmsghdr*) ptr;

		/* Check if the header is valid */
		if((NLMSG_OK(nlmsg, received_bytes) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR)) {
		    close(sock);
			return false;
		}

		/* If we received all data break */
		if(nlh->nlmsg_type == NLMSG_DONE) {
		    break;
		} else {
		    ptr += received_bytes;
		    msg_len += received_bytes;
		}

		/* Break if its not a multi part message */
		if((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0) {
		    break;
		}
	} while((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

	/* parse response */
	for(; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes)) {
		/* Get the route data */
		route_entry = (struct rtmsg*)NLMSG_DATA(nlh);

		/* We are just interested in main routing table */
		if(route_entry->rtm_table != RT_TABLE_MAIN) {
			continue;
		}

		route_attribute = (struct rtattr*)RTM_RTA(route_entry);
		route_attribute_len = RTM_PAYLOAD(nlh);

		bool set_gateway = false;
		bool set_dev = false;

		/* Loop through all attributes */
		for(; RTA_OK(route_attribute, route_attribute_len); route_attribute = RTA_NEXT(route_attribute, route_attribute_len)) {
			switch(route_attribute->rta_type) {
				case RTA_OIF: {
					if_indextoname(*(int*)RTA_DATA(route_attribute), dev);
					set_dev = true;
				}
				break;
				case RTA_GATEWAY: {
					*gateway = *(struct in_addr*)RTA_DATA(route_attribute);
					set_gateway = true;
				}
				break;
				default:
				break;
			}
		}

		if(set_gateway && set_dev) {
			break;
		}
	}

	close(sock);
	return true;
}

char *chipvpn_format_bytes(uint64_t bytes) {
	char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if(bytes > 1024) {
		for (i = 0; (bytes / 1024) > 0 && i < length - 1; i++, bytes /= 1024) {
			dblBytes = bytes / 1024.0;
		}
	}

	static char output[200];
	sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
	return output;
}

void add_route(struct in_addr src, struct in_addr mask, struct in_addr dst, char *dev) {
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	struct rtentry entry;
	memset(&entry, 0, sizeof(entry));

	struct sockaddr_in *addr = (struct sockaddr_in*)&(entry.rt_dst);
	addr->sin_family = AF_INET;
	addr->sin_addr = src;

	addr = (struct sockaddr_in*)&(entry.rt_genmask);
	addr->sin_family = AF_INET;
	addr->sin_addr = mask;

	addr = (struct sockaddr_in*)&(entry.rt_gateway);
	addr->sin_family = AF_INET;
	addr->sin_addr = dst;

	entry.rt_dev = strdup(dev);
	entry.rt_flags = RTF_UP | RTF_GATEWAY;
	entry.rt_metric = 0;

	if(ioctl(fd, SIOCADDRT, &entry) < 0) {

	}
	close(fd);
}

void read_config(const char *path) {
	FILE *fp = fopen(path, "r");
	if(!fp) {
		fprintf(stderr, "config read failed\n");
		exit(1);
	}

	char line[8192];

	while(fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;

		printf("%s\n", line);
	}

	fclose(fp);
}

volatile sig_atomic_t quit = 0;

void terminate(int type) {
	quit = 1;
}

int main(int argc, char const *argv[]) {
	/* code */

	printf("chipvpn 1.6\n"); 

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);

	chipvpn_device_t *device = chipvpn_device_create();
	if(!device) {
		fprintf(stderr, "unable to create device\n");
		exit(1);
	}
	chipvpn_device_set_address(device, "10.128.0.2", 16);
	chipvpn_device_set_mtu(device, 1400);
	chipvpn_device_set_enabled(device);

	chipvpn_peer_t *peer = chipvpn_peer_create();
	if(!peer) {
		fprintf(stderr, "unable to create peer\n");
		exit(1);
	}
	chipvpn_peer_set_endpoint(peer, "157.245.205.9", 443);
	chipvpn_peer_set_allow(peer, "0.0.0.0", 0);
	chipvpn_peer_set_key(peer, "qLG8fqA5n5JHMD2ZAFlqznWVRMBdNWcv3upcGDpPxfcHw8l25r3Rat4bygAYbzfn");
	chipvpn_peer_insert(device, peer);

	chipvpn_t *vpn = chipvpn_create(device, NULL);
	if(!vpn) {
		fprintf(stderr, "unable to create vpn\n");
		exit(1);
	}

	chipvpn_peer_state_e current_state = PEER_DISCONNECTED;

	while(!quit) {
		chipvpn_wait(vpn);
		chipvpn_service(vpn);

		// read_config("config.txt");

		if(peer->state == PEER_DISCONNECTED) {
			chipvpn_peer_connect(peer, 10000);
		}

		// printf("%li %li\n", peer->tx, peer->rx);

		if(current_state != peer->state) {
			switch(peer->state) {
				case PEER_CONNECTING: {
					printf("current status: peer_connectING\n");
				}
				break;
				case PEER_CONNECTED: {
					printf("current status: peer_connected\n");
					struct in_addr src = {};
					struct in_addr mask = {};
					struct in_addr dst = {};

					src.s_addr = inet_addr("157.245.205.9");
					mask.s_addr = inet_addr("255.255.255.255");
					dst.s_addr = inet_addr("192.168.10.1");

					char dev[128];
					chipvpn_get_gateway(&dst, dev);

					printf("%s\n", dev);

					add_route(src, mask, dst, dev);

					src.s_addr = inet_addr("0.0.0.0");
					mask.s_addr = inet_addr("128.0.0.0");
					dst.s_addr = inet_addr("10.128.0.1");
					add_route(src, mask, dst, device->dev);

					src.s_addr = inet_addr("128.0.0.0");
					mask.s_addr = inet_addr("128.0.0.0");
					dst.s_addr = inet_addr("10.128.0.1");
					add_route(src, mask, dst, device->dev);
				}
				break;
				case PEER_DISCONNECTING: {
					printf("current status: peer_disconnectING\n");
				}
				break;
				case PEER_DISCONNECTED: {
					printf("current status: peer_disconnected\n");
				}
				break;
			}
			current_state = peer->state;
		}
	}

	printf("cleanup\n");

	chipvpn_peer_disconnect(peer, 10000);

	chipvpn_device_free(device);
	chipvpn_cleanup(vpn);

	return 0;
}