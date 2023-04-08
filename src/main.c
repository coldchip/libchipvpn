#include <string.h>
#include <stdbool.h>
#include "chipvpn.h"

int main(int argc, char const *argv[]) {
    if(argc > 1) {
        chipvpn_setup((char *)argv[1]);
    } else {
        chipvpn_error("args error");
    }

    return 0;
}