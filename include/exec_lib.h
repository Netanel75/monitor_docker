#ifndef __EXEC_LIB__
#define __EXEC_LIB__

#include <stdbool.h>

#include "mbuf.h"

typedef int (*sync_cb_t)(struct mbuf *buffer);

/**
 * @brief execute executables, and return stdoout/stderr to the user
 * @param[in] sync_cb used as callback for the user to handle the data
 * @param[in] cmd     the command to execute the executable
 *
 * @returns 0 for success
*/
int exec_proccess(char **cmd, sync_cb_t sync_cb);

#endif
