/* radare - LGPL - Copyright 2012 - pancake<nopcode.org>
				2013 - condret		*/

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/m8c/m8casm.h"

static int m8c_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data,
		       int len, RAnalOpMask mask)
{

	ut8 opcode = data[0];
	int16_t offset;


	memset(op, '\0', sizeof(RAnalOp));
	op->addr = addr;
	op->size = 1;
	op->type = R_ANAL_OP_TYPE_UNK;

	if (opcode & 0x80)
		opcode = 0x78 + (opcode >> 4);

	if (opcode > 0x87) {
		return 1;
	}
	op->size = instructions[opcode].insLength;
	op->type = instructions[opcode].type;

	switch (opcode) {
	case 0x7c: /* LCALL */
		op->jump = data[1] << 8 | data[2];
		break;
	case 0x7d: /* LJMP */
		op->jump = data[1] << 8 | data[2];
		break;
	case 0x80: /* JMP */
		offset = ((data[0] & 0x0f) << 8 | data[1]);
		offset = (offset & 0x7ff) - (offset & 0x800);
		op->jump = addr + 1 + offset;
		break;
	case 0x81: /* CALL */
		offset = ((data[0] & 0x0f) << 8 | data[1]);
		offset = (offset & 0x7ff) - (offset & 0x800);
		op->jump = addr + 2 + offset;
		break;
	case 0x82: /* JZ */
	case 0x83: /* JNZ */
	case 0x84: /* JC */
	case 0x85: /* JNC */
	case 0x86: /* JACC */
		offset = ((data[0] & 0x0f) << 8 | data[1]);
		offset = (offset & 0x7ff) - (offset & 0x800);
		op->jump = addr + 1 + offset;
		op->fail = addr + 2;
		break;
	}

	op->nopcode = (op->type == R_ANAL_OP_TYPE_UNK);

	r_strbuf_init(&op->esil);

	switch (instructions[opcode].operands) {
	case NO_OPER:
	case RET:
		r_strbuf_set(&op->esil, instructions[opcode].esil_text);
		break;
	case SRC_IMM:
	case PSW_AND:
	case PSW_OR:
	case PSW_XOR:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      data[1]);
		break;
	case SRC_DIR:
	case DST_DIR:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      DIR_MEM_ADDR, data[1]);
		break;
	case SRC_IDX:
	case DST_IDX:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      data[1], IDX_MEM_ADDR);
		break;
	case DST_DIR_SRC_IMM:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      data[2], DIR_MEM_ADDR, data[1]);
		break;
	case DST_IDX_SRC_IMM:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      data[2], data[1], IDX_MEM_ADDR);
		break;
	case DST_DIR_SRC_DIR:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      DIR_MEM_ADDR, data[2], DIR_MEM_ADDR, data[1]);
		break;
		break;
	case SRC_INDPI:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      INDIR_RD_ADDR, data[1]);
		break;
	case DST_INDPI:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      INDIR_WR_ADDR, data[1], INDIR_WR_ADDR, data[1]);
		break;
	case REG_SRC_DIR:
		break;
	case REG_SRC_IDX:
		break;
	case REG_DST_DIR:
		break;
	case REG_DST_IDX:
		break;
	case REG_DST_DIR_SRC_IMM:
		break;
	case REG_DST_DIR_SRC_IMM_MOV:
		break;
	case REG_DST_IDX_SRC_IMM:
		break;
	case ABS16:
		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      (data[2] << 8) + data[1]);
		break;
	case REL12:
	case REL12_CALL:
		offset = 2 + ((data[0] & 0x0f) << 8) + data[1];

		if (offset > 2047)
			offset = -(0x1000 - offset);

		r_strbuf_setf(&op->esil, instructions[opcode].esil_text,
			      offset);
		break;
	case UNK:
		r_strbuf_set(&op->esil, "TODO");
		break;
	default:
		r_strbuf_set(&op->esil, "TODO");
	}

	return op->size;
}

static bool set_reg_profile(RAnal *anal)
{
	char *p =
		"=PC	pc\n"
		"=SP	sp\n"

		"gpr	sp	.8	5	0\n"
		"gpr	A	.8	4	0\n"
		"gpr	X	.8	3	0\n"

		"gpr	CPU_F	.8	2	0\n"
		"gpr	GIE	.1	2.0	0\n"
		"gpr	ZF	.1	2.1	0\n"
		"gpr	CF	.1	2.2	0\n"
		"gpr	XIO	.1	2.4	0\n"
		"gpr	Pg0	.1	2.6	0\n"
		"gpr	Pg1	.1	2.7	0\n"

		"gpr	pc	.16	0	0\n"
		"gpr	pch	.8	8	0\n"
		"gpr	pcl	.8	0	0\n";

	return r_reg_set_profile_string(anal->reg, p);
}

static int esil_m8c_init(RAnalEsil *esil)
{
	if (!esil) {
		return false;
	}

	esil->verbose = 2;

	return true;
}

static int esil_m8c_fini(RAnalEsil *esil)
{
	return true;
}


RAnalPlugin r_anal_plugin_m8c = {
	.name = "m8c",
	.arch = "m8c",
	.license = "LGPL3",
	.bits = 8,
	.set_reg_profile = &set_reg_profile,
	.desc = "Cypress PSoC 1 code analysis plugin",
	.op = &m8c_anal_op,
	.esil = true,
	.esil_init = esil_m8c_init,
	.esil_fini = esil_m8c_fini,
};

#ifndef CORELIB
RLibStruct radare_plugin = {.type = R_LIB_TYPE_ANAL,
			    .data = &r_anal_plugin_m8c,
			    .version = R2_VERSION};
#endif
