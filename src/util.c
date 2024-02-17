#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

char *strdup(const char *s) {
	size_t len = strlen(s) + 1;
	void *new = malloc(len);
	if (new == NULL) {
		return NULL;
	}
	return (char *) memcpy(new, s, len);
}

char* str_replace(const char* s, const char* oldW, const char* newW) { 
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

bool get_gateway(char *ip) {
	bool success = true;

	char cmd[] = "ip route show default | awk '/default/ {print $3}'";
	FILE* fp = popen(cmd, "r");

	if(fgets(ip, 16, fp) == NULL){
		success = false;
	}

	ip[15] = '\0';

	int i = 0;
	while((ip[i] >= '0' && ip[i] <= '9') || ip[i] == '.') {
		i++;
	}

	ip[i] = 0;

	pclose(fp);

	return success;
}