#ifndef DRGN_REMOTE_H
#define DRGN_REMOTE_H

#include "drgn.h"

/* GDB-based remote memory access */
struct drgn_error *
drgn_program_enable_remote_gdb(struct drgn_program *prog);

/* QMP-based remote memory access */
struct drgn_error *
drgn_program_enable_remote_qmp(struct drgn_program *prog);

#endif