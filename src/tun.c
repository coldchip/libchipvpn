/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@chip.sg>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README for more details.
 */

#include "tun.h"
#include "socket.h"
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "address.h"

#ifdef _WIN32
	#include <winioctl.h>
	/* From OpenVPN tap driver, common.h */
	#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
	#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
	#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE (10, METHOD_BUFFERED)

	#define MAX_KEY_LENGTH 255
	#define MAX_VALUE_NAME 16383
	#define NETWORK_ADAPTERS "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
	#define NETWORK_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#else
    #include <linux/if.h>
	#include <linux/if_tun.h>
	#include <sys/ioctl.h>
	#include <netinet/in.h>
#endif

chipvpn_tun_t *chipvpn_tun_create(const char *dev) {
	chipvpn_tun_t *tun = malloc(sizeof(chipvpn_tun_t));
	if(!tun) {
		return NULL;
	}

	#ifdef _WIN32

	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
		return NULL;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		return NULL;
	}

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	sa.sin_port = htons(38477);

	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		return NULL;
	}

	tun->fd = fd;

	char *deviceid = chipvpn_tun_regquery(NETWORK_ADAPTERS);
	if(!deviceid) {
		return NULL;
	}

	get_name(tun->dev, sizeof(dev), deviceid);

	char buf[60];
	snprintf(buf, sizeof buf, "\\\\.\\Global\\%s.tap", deviceid);
	HANDLE tun_fd = CreateFile(buf, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
	if(tun_fd == INVALID_HANDLE_VALUE) {
		// int errcode = GetLastError();
		return NULL;
	}

	tun->tun_fd = tun_fd;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) chipvpn_tun_reader, tun, 0, NULL);
	// CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) chipvpn_tun_writer, tun, 0, NULL);

	#else

	int fd = open("/dev/net/tun", O_RDWR);
	if(fd < 0) {
		return NULL;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if(dev) {
		if(strlen(dev) > IFNAMSIZ) {
			return NULL;
		}

		if(*dev) {
			strcpy(ifr.ifr_name, dev);
		}
	}

	if(ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		close(fd);
		return NULL;
	}

	tun->fd = fd;
	strcpy(tun->dev, ifr.ifr_name);

	#endif

	return tun;
}

#ifdef _WIN32

char *chipvpn_tun_regquery(char *key_name) {
	HKEY adapters, adapter;
	DWORD i, ret, len;
	char *deviceid = NULL;
	DWORD sub_keys = 0;

	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(key_name), 0, KEY_READ, &adapters);
	if (ret != ERROR_SUCCESS) {
		return NULL;
	}

	ret = RegQueryInfoKey(adapters,	NULL, NULL, NULL, &sub_keys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (ret != ERROR_SUCCESS) {
		return NULL;
	}

	if (sub_keys <= 0) {
		return NULL;
	}

	/* Walk througt all adapters */
    for (i = 0; i < sub_keys; i++) {
		char new_key[MAX_KEY_LENGTH];
		char data[256];
		TCHAR key[MAX_KEY_LENGTH];
		DWORD keylen = MAX_KEY_LENGTH;

		/* Get the adapter key name */
		ret = RegEnumKeyEx(adapters, i, key, &keylen, NULL, NULL, NULL, NULL);
		if (ret != ERROR_SUCCESS) {
			continue;
		}
		
		/* Append it to NETWORK_ADAPTERS and open it */
		snprintf(new_key, sizeof new_key, "%s\\%s", key_name, key);
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(new_key), 0, KEY_READ, &adapter);
		if (ret != ERROR_SUCCESS) {
			continue;
		}

		/* Check its values */
		len = sizeof data;
		ret = RegQueryValueEx(adapter, "ComponentId", NULL, NULL, (LPBYTE)data, &len);
		if (ret != ERROR_SUCCESS) {
			/* This value doesn't exist in this adaptater tree */
			goto clean;
		}
		/* If its a tap adapter, its all good */
		if (strncmp(data, "tap", 3) == 0) {
			DWORD type;

			len = sizeof data;
			ret = RegQueryValueEx(adapter, "NetCfgInstanceId", NULL, &type, (LPBYTE)data, &len);
			if (ret != ERROR_SUCCESS) {
				goto clean;
			}
			deviceid = strdup(data);
			break;
		}
clean:
		RegCloseKey(adapter);
	}
	RegCloseKey(adapters);
	return deviceid;
}

void get_name(char *ifname, int namelen, char *dev_name) {
	char path[256];
	char name_str[256] = "Name";
	LONG status;
	HKEY conn_key;
	DWORD len;
	DWORD datatype;

	memset(ifname, 0, namelen);

	snprintf(path, sizeof(path), "%s\\%s\\Connection", NETWORK_KEY, dev_name);
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &conn_key);
	if (status != ERROR_SUCCESS) {
		fprintf(stderr, "Could not look up name of interface %s: error opening key\n", dev_name);
		RegCloseKey(conn_key);
		return;
	}
	len = namelen;
	status = RegQueryValueEx(conn_key, name_str, NULL, &datatype, (LPBYTE)ifname, &len);
	if (status != ERROR_SUCCESS || datatype != REG_SZ) {
		fprintf(stderr, "Could not look up name of interface %s: error reading value\n", dev_name);
		RegCloseKey(conn_key);
		return;
	}
	RegCloseKey(conn_key);
}

#endif

bool chipvpn_tun_setip(chipvpn_tun_t *tun, chipvpn_address_t *network, int mtu, int qlen) {
	#ifdef _WIN32

	if(!chipvpn_tun_ifup(tun)) {
		return false;
	}

	DWORD len;
	unsigned long psock[3];

	if(!DeviceIoControl(tun->tun_fd, TAP_IOCTL_GET_VERSION, &psock, sizeof(psock), &psock, sizeof(psock), &len, NULL)) {
		return NULL;
	}

	psock[0] = inet_addr("10.0.2.2"); 
	psock[1] = inet_addr("10.0.2.0"); /* network addr */
    psock[2] = inet_addr("255.255.255.0"); 

	if(!DeviceIoControl(tun->tun_fd, TAP_IOCTL_CONFIG_TUN, &psock, sizeof(psock), &psock, sizeof(psock), &len, NULL)) {
		return false;
	}

	char cmdline[512];
	fprintf(stderr, "Setting IP of interface '%s' to %s (can take a few seconds)...\n", tun->dev, "10.0.2.2");
	snprintf(cmdline, sizeof(cmdline), "netsh interface ip set address \"%s\" static %s %s", tun->dev, "10.0.2.2", "255.255.255.0");
	system(cmdline);

	fprintf(stderr, "Setting MTU of interface '%s' to %s (can take a few seconds)...\n", tun->dev, "10.0.2.2");
	snprintf(cmdline, sizeof(cmdline), "netsh interface ipv4 set subinterface \"%s\" mtu=%i", tun->dev, mtu);
	system(cmdline);

	return true;

	#else
	if(tun) {
		struct ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;

		strcpy(ifr.ifr_name, tun->dev);

		struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		addr->sin_addr.s_addr = network->ip;
		ioctl(fd, SIOCSIFADDR, &ifr);

		addr->sin_addr.s_addr = htonl((0xFFFFFFFFUL << (32 - network->prefix)) & 0xFFFFFFFFUL);
		ioctl(fd, SIOCSIFNETMASK, &ifr);

		ifr.ifr_mtu = mtu;
		ioctl(fd, SIOCSIFMTU, &ifr);

		ifr.ifr_qlen = qlen;
		ioctl(fd, SIOCSIFTXQLEN, &ifr);

	    close(fd);
	    return true;
	}
	return false;
	#endif
}

bool chipvpn_tun_ifup(chipvpn_tun_t *tun) {
	#ifdef _WIN32

	int one = 1;

	DWORD len;
	if(!DeviceIoControl(tun->tun_fd, TAP_IOCTL_SET_MEDIA_STATUS, &one, sizeof(one), &one, sizeof(one), &len, NULL)) {
		return false;
	}
	return true;
	#else
	if(tun) {
		struct ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;

		strcpy(ifr.ifr_name, tun->dev);

		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		ifr.ifr_flags |= IFF_UP;
		ioctl(fd, SIOCSIFFLAGS, &ifr);

	    close(fd);
	    return true;
	}
	return false;
	#endif
}

DWORD WINAPI chipvpn_tun_reader(LPVOID arg) {
	chipvpn_tun_t *tun = (chipvpn_tun_t*)arg;

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	sa.sin_port = htons(38477);

	char buf[64*1024];
	int len;
	int res;
	OVERLAPPED olpd;

	chipvpn_address_t f;
	if(!chipvpn_address_set_ip(&f, "127.0.0.1")) {
		printf("invalid ip address\n");
	}
	f.port = 0;

	chipvpn_socket_t *sock = chipvpn_socket_create();
	if(!chipvpn_socket_bind(sock, &f)) {
		printf("socket bind failed\n");
	}

	olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	while(TRUE) {
		olpd.Offset = 0;
		olpd.OffsetHigh = 0;
		res = ReadFile(tun->tun_fd, buf, sizeof(buf), (LPDWORD) &len, &olpd);
		if (!res) {
			WaitForSingleObject(olpd.hEvent, INFINITE);
			res = GetOverlappedResult(tun->tun_fd, &olpd, (LPDWORD) &len, FALSE);
			res = sendto(sock->fd, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa));
		}
	}

	return 0;
}

DWORD WINAPI chipvpn_tun_writer(LPVOID arg) {
	chipvpn_tun_t *tun = (chipvpn_tun_t*)arg;

	char buf[8192];

	struct sockaddr_in sa;
	int len = 0;
	while(true) {
		int r = recvfrom(tun->fd, buf, sizeof(buf), MSG_WAITALL, (struct sockaddr*)&sa, &len);
		if(r > 0) {
			printf("RECV %i\n", r);
			WriteFile(tun->tun_fd, buf, r, NULL, NULL);
		}
	}
}

int chipvpn_tun_read(chipvpn_tun_t *tun, void *buf, int size) {
	#ifdef _WIN32
	return recv(tun->fd, buf, size, 0);
	#else
	return read(tun->fd, buf, size);
	#endif
}

int chipvpn_tun_write(chipvpn_tun_t *tun, void *buf, int size) {
	#ifdef _WIN32
	DWORD written;
	DWORD res;
	OVERLAPPED olpd;

	olpd.Offset = 0;
	olpd.OffsetHigh = 0;
	olpd.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	res = WriteFile(tun->tun_fd, buf, size, &written, &olpd);
	if (!res && GetLastError() == ERROR_IO_PENDING) {
		WaitForSingleObject(olpd.hEvent, INFINITE);
		res = GetOverlappedResult(tun->tun_fd, &olpd, &written, FALSE);
		if (written != size) {
			return -1;
		}
	}
	return written;
	#else
	return write(tun->fd, buf, size);
	#endif
}

void chipvpn_tun_free(chipvpn_tun_t *tun) {
	if(tun) {
		#ifdef _WIN32
		CloseHandle(tun->tun_fd);
		closesocket(tun->fd);
		#else
		if(*tun->dev != '\0') {
			struct ifreq ifr;
			ifr.ifr_addr.sa_family = AF_INET;

			strcpy(ifr.ifr_name, tun->dev);

			int fd = socket(AF_INET, SOCK_DGRAM, 0);

			ifr.ifr_flags = ifr.ifr_flags & ~IFF_UP;
			ioctl(fd, SIOCSIFFLAGS, &ifr);

		    close(fd);
		}
		close(tun->fd);
		#endif
		free(tun);
	}
}