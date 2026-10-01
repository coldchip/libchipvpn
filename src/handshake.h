#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "noise.h"

bool               chipvpn_handshake_produce_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_packet_auth_t *packet);
chipvpn_peer_t    *chipvpn_handshake_consume_connect(chipvpn_device_t *device, chipvpn_packet_auth_t *packet);
bool               chipvpn_handshake_produce_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet);
chipvpn_peer_t    *chipvpn_handshake_consume_reply(chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet);

bool               chipvpn_handshake_begin_session(chipvpn_peer_t *peer, bool is_initiator);

#endif