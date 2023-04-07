#include <string.h>
#include <stdbool.h>
#include "chipvpn.h"
#include "config.h"

int main(int argc, char const *argv[]) {
    if(argc > 1) {
        chipvpn_config_t config;
        chipvpn_config_load(&config, argv[1]);
        chipvpn_setup(&config);
    } else {
        chipvpn_error("args error");
    }

    return 0;
}