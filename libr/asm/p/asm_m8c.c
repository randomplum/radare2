/* radare - LGPL - Copyright 2012-2017 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/m8c/m8c.c"

static int do_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = m8cDisass (op, buf, len, a->pc);
}

#if 0
static int do_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return op->size = m8casm (op->buf, buf);
}
#endif

RAsmPlugin r_asm_plugin_m8c = {
	.name = "m8c",
	.desc = "Cypress PSoC 1",
	.license = "GPL",
	.arch = "m8c",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &do_disassemble,
//	.assemble = &do_assemble,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_m8c,
	.version = R2_VERSION
};
#endif
