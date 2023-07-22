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
	#include <netioapi.h>
	#include <iptypes.h>
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <iphlpapi.h>
	#include <winioctl.h>
	/* From OpenVPN tap driver, common.h */
	#define TAP_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
	#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE(1, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE(2, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE(3, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE(4, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE(5, METHOD_BUFFERED)
	#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE(6, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE(7, METHOD_BUFFERED)
	#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE(8, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE(9, METHOD_BUFFERED)
	#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE(10, METHOD_BUFFERED)

	#define MAX_KEY_LENGTH 255
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

	chipvpn_socket_t *frontend = chipvpn_socket_create();
	chipvpn_socket_t *backend = chipvpn_socket_create();
	if(!frontend || !backend) {
		chipvpn_error("unable to create socket");
	}

	chipvpn_address_t frontend_addr, backend_addr;
	if(!chipvpn_address_set_ip(&frontend_addr, "127.0.0.1") || !chipvpn_address_set_ip(&backend_addr, "127.0.0.1")) {
		chipvpn_error("invalid ip address");
	}

	frontend_addr.port = 48372;
	backend_addr.port = 48373;

	if(!chipvpn_socket_bind(frontend, &frontend_addr) || !chipvpn_socket_bind(backend, &backend_addr)) {
		chipvpn_error("socket bind failed");
	}

	tun->frontend_addr = frontend_addr;
	tun->backend_addr = backend_addr;
	tun->frontend = frontend;
	tun->backend = backend;

	char *deviceid = chipvpn_tun_regquery(NETWORK_ADAPTERS);
	if(!deviceid) {
		return NULL;
	}

	char buf[256];
	snprintf(buf, sizeof buf, "\\\\.\\Global\\%s.tap", deviceid);
	HANDLE tun_fd = CreateFile(buf, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
	if(tun_fd == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	tun->reader_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)chipvpn_tun_reader, tun, 0, NULL);
	tun->writer_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)chipvpn_tun_writer, tun, 0, NULL);

	tun->fd = frontend->fd;
	tun->tun_fd = tun_fd;
	strcpy(tun->dev, deviceid);
	free(deviceid);

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
	if(ret != ERROR_SUCCESS) {
		return NULL;
	}

	ret = RegQueryInfoKey(adapters,	NULL, NULL, NULL, &sub_keys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if(ret != ERROR_SUCCESS) {
		return NULL;
	}

	if(sub_keys <= 0) {
		return NULL;
	}

	/* Walk througt all adapters */
	for(i = 0; i < sub_keys; i++) {
		char new_key[MAX_KEY_LENGTH];
		char data[256];
		TCHAR key[MAX_KEY_LENGTH];
		DWORD keylen = MAX_KEY_LENGTH;

		/* Get the adapter key name */
		ret = RegEnumKeyEx(adapters, i, key, &keylen, NULL, NULL, NULL, NULL);
		if(ret != ERROR_SUCCESS) {
			continue;
		}
		
		/* Append it to NETWORK_ADAPTERS and open it */
		snprintf(new_key, sizeof new_key, "%s\\%s", key_name, key);
		ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(new_key), 0, KEY_READ, &adapter);
		if(ret != ERROR_SUCCESS) {
			continue;
		}

		/* Check its values */
		len = sizeof data;
		ret = RegQueryValueEx(adapter, "ComponentId", NULL, NULL, (LPBYTE)data, &len);
		if(ret != ERROR_SUCCESS) {
			/* This value doesn't exist in this adaptater tree */
			goto clean;
		}
		/* If its a tap adapter, its all good */
		if(strncmp(data, "tap", 3) == 0) {
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

IP_ADAPTER_INFO *chipvpn_get_adapter_list() {
	ULONG size = 0;
	IP_ADAPTER_INFO *pi = NULL;
	DWORD status;

	if((status = GetAdaptersInfo(NULL, &size)) == ERROR_BUFFER_OVERFLOW) {
		pi = (PIP_ADAPTER_INFO)malloc(size * sizeof(char));
		if((status = GetAdaptersInfo(pi, &size)) != NO_ERROR) {
			pi = NULL;
		}
	}
	return pi;
}

IP_ADAPTER_INFO *chipvpn_get_adapter(IP_ADAPTER_INFO *ai, char *guid) {
	if(ai && guid) {
		for(IP_ADAPTER_INFO *a = ai; a != NULL; a = a->Next) {
			if(strcmp(guid, a->AdapterName) == 0) {
				return a;
			}
		}
	}
	return NULL;
}

#endif

bool chipvpn_tun_set_ip(chipvpn_tun_t *tun, chipvpn_address_t *network) {
	#ifdef _WIN32

	if(!chipvpn_tun_ifup(tun)) {
		return false;
	}

	uint32_t mask = 0;
	if(network->prefix == 0) {
		mask = 0;
	} else {
		mask = htonl((0xFFFFFFFFUL << (32 - network->prefix)) & 0xFFFFFFFFUL);
	}

	uint32_t psock[3];
	psock[0] = network->ip; 
	psock[1] = network->ip & mask;
	psock[2] = mask;

	DWORD len;
	if(!DeviceIoControl(tun->tun_fd, TAP_IOCTL_CONFIG_TUN, &psock, sizeof(psock), &psock, sizeof(psock), &len, NULL)) {
		return false;
	}

	IP_ADAPTER_INFO *list = chipvpn_get_adapter_list();
	IP_ADAPTER_INFO *adapter = chipvpn_get_adapter(list, tun->dev);
	if(!adapter) {
		chipvpn_error("unable to locate adapter");
	}

	IP_ADDR_STRING *ip = &adapter->IpAddressList;
	while(ip) {
		if(DeleteIPAddress(ip->Context) == NO_ERROR) {
			chipvpn_log("deleting previous ip address set on the interface successfully");
		}
		ip = ip->Next;
	}

	DWORD ctx, ins;
	if(AddIPAddress(network->ip, mask, adapter->Index, &ctx, &ins) != NO_ERROR) {
		chipvpn_error("unable to set ip address on the interface");
	}

	free(list);

	return true;

	#else

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, tun->dev);

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	addr->sin_addr.s_addr = network->ip;
	ioctl(fd, SIOCSIFADDR, &ifr);

	if(network->prefix == 0) {
		addr->sin_addr.s_addr = 0;
	} else {
		addr->sin_addr.s_addr = htonl((0xFFFFFFFFUL << (32 - network->prefix)) & 0xFFFFFFFFUL);
	}

	ioctl(fd, SIOCSIFNETMASK, &ifr);

	close(fd);
	return true;
	#endif
}

bool chipvpn_tun_set_mtu(chipvpn_tun_t *tun, int mtu) {
	#ifdef _WIN32

	IP_ADAPTER_INFO *list = chipvpn_get_adapter_list();
	IP_ADAPTER_INFO *adapter = chipvpn_get_adapter(list, tun->dev);
	if(!adapter) {
		chipvpn_error("unable to locate adapter");
	}

	MIB_IPINTERFACE_ROW ipiface;
	InitializeIpInterfaceEntry(&ipiface);
	ipiface.Family = AF_INET;
	ipiface.InterfaceIndex = adapter->Index;
	if(GetIpInterfaceEntry(&ipiface) != NO_ERROR) {
		chipvpn_error("unable to set interface mtu");
	}
	ipiface.SitePrefixLength = 0;
	ipiface.UseAutomaticMetric = false;
	ipiface.NlMtu = mtu;
	ipiface.Metric = 1;
	if(SetIpInterfaceEntry(&ipiface) != NO_ERROR) {
		chipvpn_error("unable to set interface mtu");
	}

	free(list);
	return true;

	#else

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, tun->dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_mtu = mtu;
	ioctl(fd, SIOCSIFMTU, &ifr);

	close(fd);
	return true;
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

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, tun->dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_flags |= IFF_UP;
	ioctl(fd, SIOCSIFFLAGS, &ifr);

	close(fd);
	return true;
	#endif
}

bool chipvpn_tun_ifdown(chipvpn_tun_t *tun) {
	#ifdef _WIN32

	int zero = 0;

	DWORD len;
	if(!DeviceIoControl(tun->tun_fd, TAP_IOCTL_SET_MEDIA_STATUS, &zero, sizeof(zero), &one, sizeof(one), &len, NULL)) {
		return false;
	}
	return true;

	#else

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, tun->dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_flags &= ~IFF_UP;
	ioctl(fd, SIOCSIFFLAGS, &ifr);

	close(fd);
	return true;
	#endif
}

#ifdef _WIN32

DWORD WINAPI chipvpn_tun_reader(LPVOID arg) {
	chipvpn_tun_t *tun = (chipvpn_tun_t*)arg;

	char buf[64 * 1024];
	int len;
	int res;
	OVERLAPPED olpd;
	olpd.hEvent = CreateEvent(NULL, true, false, NULL);

	while(true) {
		olpd.Offset = 0;
		olpd.OffsetHigh = 0;
		res = ReadFile(tun->tun_fd, buf, sizeof(buf), (LPDWORD)&len, &olpd);
		if (!res) {
			WaitForSingleObject(olpd.hEvent, INFINITE);
			res = GetOverlappedResult(tun->tun_fd, &olpd, (LPDWORD)&len, false);
			chipvpn_socket_write(tun->backend, buf, len, &tun->frontend_addr);
		}
	}

	return 0;
}

DWORD WINAPI chipvpn_tun_writer(LPVOID arg) {
	chipvpn_tun_t *tun = (chipvpn_tun_t*)arg;

	char buf[64 * 1024];
	DWORD written;
	DWORD res;
	OVERLAPPED olpd;
	olpd.hEvent = CreateEvent(NULL, true, false, NULL);

	while(true) {
		int r = chipvpn_socket_read(tun->backend, buf, sizeof(buf), NULL);
		if(r > 0) {
			olpd.Offset = 0;
			olpd.OffsetHigh = 0;
			res = WriteFile(tun->tun_fd, buf, r, &written, &olpd);
			if (!res && GetLastError() == ERROR_IO_PENDING) {
				WaitForSingleObject(olpd.hEvent, INFINITE);
				res = GetOverlappedResult(tun->tun_fd, &olpd, &written, false);
				if (written != r) {
					return -1;
				}
			}
		}
	}

	return 0;
}

#endif

int chipvpn_tun_read(chipvpn_tun_t *tun, void *buf, int size) {
	#ifdef _WIN32
	return chipvpn_socket_read(tun->frontend, buf, size, NULL);
	#else
	return read(tun->fd, buf, size);
	#endif
}

int chipvpn_tun_write(chipvpn_tun_t *tun, void *buf, int size) {
	#ifdef _WIN32
	return chipvpn_socket_write(tun->frontend, buf, size, &tun->backend_addr);
	#else
	return write(tun->fd, buf, size);
	#endif
}

void chipvpn_tun_free(chipvpn_tun_t *tun) {
	#ifdef _WIN32
	TerminateThread(tun->reader_thread, 0);
	CloseHandle(tun->reader_thread);
	TerminateThread(tun->writer_thread, 0);
	CloseHandle(tun->writer_thread);

	CloseHandle(tun->tun_fd);
	chipvpn_socket_free(tun->frontend);
	chipvpn_socket_free(tun->backend);

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