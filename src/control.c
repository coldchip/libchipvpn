#include <stddef.h>
#include "control.h"

chipvpn_control_t *chipvpn_control_create(const char *path) {
	chipvpn_control_t *control = malloc(sizeof(chipvpn_control_t));
	if(!control) {
		return NULL;
	}

	mkfifo(path, 0666);

	strcpy(control->path, path);

	return control;
}

void chipvpn_control_free(chipvpn_control_t *control) {
	unlink(control->path);
	free(control);
}