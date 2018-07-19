
#include <r_asm.h>
#include <r_types.h>
#include <r_util.h>
#include <stdio.h>
#include <string.h>
#include "m8casm.h"

static int disassemHandlerRel12(const ut8 *memory, instruction_t *ins,
				RStrBuf *buffer, ut64 pc)
{
	ut32 offset = 2 + ((memory[0] & 0x0f) << 8) + memory[1] - 1;

	if (offset > 2047)
		offset = -(0x1000 - offset);

	r_strbuf_setf(buffer, ins->text, (ut32)pc + offset);
	return 1;
}

static int disassemHandlerRel12Call(const ut8 *memory, instruction_t *ins,
				    RStrBuf *buffer, ut64 pc)
{
	ut32 offset = 2 + ((memory[0] & 0x0f) << 8) + memory[1];

	if (offset > 2047)
		offset = -(0x1000 - offset);

	r_strbuf_setf(buffer, ins->text, (ut32)pc + offset);
	return 1;
}


FUNC_ATTR_USED ut8 m8cDisass(RAsmOp *op, const ut8 *buf, int len, ut64 pc)
{
	ut8 opcode = buf[0];
	int ret = -1;

	if (opcode & 0x80)
		opcode = 0x78 + (opcode >> 4);

	if (opcode > 0x87) {
		r_strbuf_setf(&op->buf_asm, "invalid");
		return 1;
	}

	switch (instructions[opcode].operands) {
	case NO_OPER:
	case RET:
		r_strbuf_setf(&op->buf_asm, instructions[opcode].text);
		break;
	case SRC_IMM:
	case SRC_DIR:
	case SRC_IDX:
	case DST_DIR:
	case DST_IDX:
	case REG_SRC_DIR:
	case REG_SRC_IDX:
	case REG_DST_DIR:
	case REG_DST_IDX:
	case SRC_INDPI:
	case DST_INDPI:
	case PSW_AND:
	case PSW_OR:
	case PSW_XOR:
		r_strbuf_setf(&op->buf_asm, instructions[opcode].text, buf[1]);
		break;
	case DST_DIR_SRC_IMM:
	case DST_IDX_SRC_IMM:
	case DST_DIR_SRC_DIR:
	case REG_DST_DIR_SRC_IMM:
	case REG_DST_DIR_SRC_IMM_MOV:
	case REG_DST_IDX_SRC_IMM:
		r_strbuf_setf(&op->buf_asm, instructions[opcode].text, buf[1], buf[2]);
		break;
	case ABS16:
		r_strbuf_setf(&op->buf_asm, instructions[opcode].text,
			((buf[1] << 8) + buf[2]));
		break;
	case REL12:
		ret = disassemHandlerRel12(buf, &instructions[opcode],
					   &op->buf_asm, pc);
		break;
	case REL12_CALL:
		ret = disassemHandlerRel12Call(buf, &instructions[opcode],
					       &op->buf_asm, pc);
		break;
	default:
		ret = -ENOENT;
	}

	if (!ret)
		return 0;

	return instructions[opcode].insLength;
}
