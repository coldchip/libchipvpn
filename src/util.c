#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>

char *chipvpn_strdup(const char *s) {
	size_t len = strlen(s) + 1;
	void *new = malloc(len);
	if (new == NULL) {
		return NULL;
	}
	return (char *) memcpy(new, s, len);
}

char* chipvpn_str_replace(const char* s, const char* oldW, const char* newW) { 
    char* result; 
    int i, cnt = 0; 
    int newWlen = strlen(newW); 
    int oldWlen = strlen(oldW); 
 
    // Counting the number of times old word 
    // occur in the string 
    for (i = 0; s[i] != '\0'; i++) { 
        if (strstr(&s[i], oldW) == &s[i]) { 
            cnt++; 
 
            // Jumping to index after the old word. 
            i += oldWlen - 1; 
        } 
    } 
 
    // Making new string of enough length 
    result = (char*)malloc(i + cnt * (newWlen - oldWlen) + 1); 
 
    i = 0; 
    while (*s) { 
        // compare the substring with the result 
        if (strstr(s, oldW) == s) { 
            strcpy(&result[i], newW); 
            i += newWlen; 
            s += oldWlen; 
        } 
        else
            result[i++] = *s++; 
    } 
 
    result[i] = '\0'; 
    return result; 
}

bool chipvpn_get_gateway(char *ip, char *dev) {
	bool success = true;

    if(ip) {
        char cmd[] = "ip route show default | awk '/default/ {print $3}'";

        FILE* fp = popen(cmd, "r");

        if(fgets(ip, 16, fp) == NULL){
        	success = false;
        }

        ip[15] = '\0';

        int i = 0;
        while(
            (ip[i] >= '0' && ip[i] <= '9') || 
            (ip[i] == '.')
        ) {
        	i++;
        }

        ip[i] = 0;

        pclose(fp);
    }

    //

    if(dev) {
        char cmd2[] = "ip route show default | awk '/default/ {print $5}'";

        FILE* fp1 = popen(cmd2, "r");

        if(fgets(dev, 16, fp1) == NULL){
            success = false;
        }

        dev[15] = '\0';

        int z = 0;
        while(
            (dev[z] >= 'a' && dev[z] <= 'z') || 
            (dev[z] >= '0' && dev[z] <= '9') || 
            (dev[z] >= 'A' && dev[z] <= 'Z') || 
            (dev[z] == '-') || 
            (dev[z] == '_')
        ) {
            z++;
        }

        dev[z] = 0;

        pclose(fp1);
    }

	return success;
}

char *chipvpn_format_bytes(uint64_t bytes) {
    char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"};
    char length = sizeof(suffix) / sizeof(suffix[0]);

    int i = 0;
    double dblBytes = bytes;

    if(bytes > 1024) {
        for(i = 0; (bytes / 1024) > 0 && i < length - 1; i++, bytes /= 1024) {
            dblBytes = bytes / 1024.0;
        }
    }

    static char output[200];
    sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
    return output;
}

bool chipvpn_secure_random(uint8_t *buf, int size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    int offset = 0, count;
    int tmp;

    while (size > 0) {
        count = size <= 8192 ? size : 8192;
        tmp = read(fd, (char *)buf + offset, count);
        if (tmp == -1 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        if (tmp == -1) return -1; /* Unrecoverable IO error */
        offset += tmp;
        size -= tmp;
    }

    close(fd);

    return true;
}

uint64_t chipvpn_get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

int chipvpn_secure_memcmp(const void *a, const void *b, size_t size) {
    const uint8_t *a_ptr = (const uint8_t *)a;
    const uint8_t *b_ptr = (const uint8_t *)b;
    uint32_t result = 0;

    for(size_t i = 0; i < size; i++) {
        result |= a_ptr[i] ^ b_ptr[i];
    }

    return result;
}
