#include "auth.h"

#include <stdio.h>
#include <unistd.h>

int main(void)
{
    const char *db_path = "server/res/users.db";
    const char *seed_path = "server/res/users.seed";
    int existed_before;

    existed_before = (access(db_path, F_OK) == 0);

    if (auth_bootstrap_from_seed_if_needed(db_path, seed_path) != 0) {
        return 1;
    }

    if (!existed_before && access(db_path, F_OK) == 0) {
        puts("OK");
    }

    return 0;
}
