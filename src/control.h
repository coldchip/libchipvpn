#ifndef CONTROL_H
#define CONTROL_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
	char path[512];
} chipvpn_control_t;

chipvpn_control_t      *chipvpn_control_create(const char *path);
void                    chipvpn_control_free(chipvpn_control_t *control);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif