#include <string.h>
#include <stdbool.h>
#include "chipvpn.h"

int main(int argc, char const *argv[]) {
    if(argc > 1) {
        if(strcmp(argv[1], "server") == 0) {
            chipvpn_setup(true);
        } else {
            chipvpn_setup(false);
        }
    } else {
        chipvpn_error("args error");
    }

    return 0;
}