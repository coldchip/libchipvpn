#ifndef DEVICE_H
#define DEVICE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include "socket.h"
#include "address.h"
#include "list.h"
#include "curve25519.h"
#include <netinet/in.h>
#include <net/if.h>

#ifdef __linux__
#define IFF_TUN 0x0001
#define IFF_NO_PI 0x1000
#define TUNSETIFF _IOW('T', 202, int)
#define TUNSETPERSIST _IOW('T', 203, int)
#endif

typedef struct chipvpn_peer chipvpn_peer_t;
typedef struct chipvpn_peer_session chipvpn_peer_session_t;

typedef enum {
    COMMAND_DEVICE_SECTION,
    COMMAND_PEER_SECTION
} chipvpn_command_section_e;

typedef struct {
    chipvpn_list_node_t node;
	int fd;
	char dev[IF_NAMESIZE + 1];
    chipvpn_list_t peers;
    chipvpn_socket_t *socket;
    uint8_t public[CURVE25519_KEY_SIZE];
    uint8_t private[CURVE25519_KEY_SIZE];
} chipvpn_device_t;

chipvpn_device_t       *chipvpn_device_create(int tun_fd);

uint32_t                chipvpn_device_generate_index(chipvpn_device_t *device);

chipvpn_peer_t         *chipvpn_device_lookup_peer_by_pubkey(chipvpn_device_t *device, const uint8_t *public);
chipvpn_peer_t         *chipvpn_device_lookup_peer_by_ip(chipvpn_device_t *device, chipvpn_address_t *ip);
chipvpn_peer_t         *chipvpn_device_lookup_peer_by_handshake(chipvpn_device_t *device, uint32_t session_id);
chipvpn_peer_t         *chipvpn_device_lookup_peer_by_session(chipvpn_device_t *device, chipvpn_peer_session_t **session, uint32_t session_id);

bool                    chipvpn_device_set_name(chipvpn_device_t *device, const char *name);
bool                    chipvpn_device_set_address(chipvpn_device_t *device, chipvpn_address_t *network);
bool                    chipvpn_device_set_mtu(chipvpn_device_t *device, int mtu);
bool                    chipvpn_device_set_enabled(chipvpn_device_t *device);
bool                    chipvpn_device_set_disabled(chipvpn_device_t *device);
bool                    chipvpn_device_set_public_key(chipvpn_device_t *device, const char *key);
bool                    chipvpn_device_set_private_key(chipvpn_device_t *device, const char *key);
void                    chipvpn_device_free(chipvpn_device_t *device);

#ifdef __cplusplus
}
#endif

#endif