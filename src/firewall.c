#include <arpa/inet.h>
#include "firewall.h"
#include "packet.h"
#include "util.h"

int chipvpn_firewall_process_ip(chipvpn_firewall_t *firewall, ip_hdr_t *ip_hdr) {
	if(ip_hdr->version != 4) {
		return 0;
	}

	if(ip_hdr->ip_p == 6) {
		tcp_hdr_t *tcp = (tcp_hdr_t *)((uint8_t*)ip_hdr + ip_hdr->ihl * 4);
		if(tcp->syn == 1) {
			uint8_t *opt = (uint8_t *)tcp + sizeof(tcp_hdr_t);
			uint8_t *opt_end = (uint8_t *)tcp + (tcp->doff * 4);

			while (opt < opt_end) {
				uint8_t kind = opt[0];
				
				if (kind == 0) break; // End of Options List
				if (kind == 1) {      // No-Operation (Padding)
					opt++;
					continue;
				}

				uint8_t len = opt[1];
				if (len < 2 || (opt + len) > opt_end) break; // Malformed option

				if (kind == 2 && len == 4) { // MSS Option (Kind: 2, Length: 4)
					uint16_t *mss_ptr = (uint16_t *)(opt + 2);
					uint16_t current_mss = ntohs(*mss_ptr);
					
					// Example: Clamp MSS to 1300 to account for tunnel overhead

					uint16_t max_mss = firewall->mss; 
					if (current_mss > max_mss) {
						uint16_t old_mss = ntohs(*mss_ptr);
						uint16_t new_mss = max_mss;

						uint32_t sum = ~ntohs(tcp->check) & 0xFFFF;
						sum += ~old_mss & 0xFFFF;
						sum += new_mss;

						while (sum >> 16) {
						    sum = (sum & 0xFFFF) + (sum >> 16);
						}

						tcp->check = htons(~sum & 0xFFFF);

						*mss_ptr = htons(new_mss);
					}
					break;
				}
				opt += len;
			}
		}
	}

	return 1;
}