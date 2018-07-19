#ifndef M8CASM_H
#define M8CASM_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <r_anal.h>

typedef struct instruction_s instruction_t;

struct instruction_s {
  char *text;
  char *esil_text;
  int cycles;
  int insLength;
  int opcode;
  int operands;
  int type;
};


enum instr_type{
  NO_OPER = 0,
  SRC_IMM,
  SRC_DIR,
  SRC_IDX,
  DST_DIR,
  DST_IDX,
  DST_DIR_SRC_IMM,
  DST_IDX_SRC_IMM,
  DST_DIR_SRC_DIR,
  SRC_INDPI,
  DST_INDPI,
  REG_SRC_DIR,
  REG_SRC_IDX,
  REG_DST_DIR,
  REG_DST_IDX,
  REG_DST_DIR_SRC_IMM,
  REG_DST_DIR_SRC_IMM_MOV,
  REG_DST_IDX_SRC_IMM,
  PSW_AND,
  PSW_OR,
  PSW_XOR,
  RET,
  ABS16,
  REL12,
  REL12_CALL,
  UNK
};

#define REG_USER_OFFSET "0x9000"
#define REG_CONF_OFFSET "0x9100"
#define MEM_OFFSET "0x8000"
#define DIR_MEM_ADDR "Pg1,1,==,?{,8,0x90D0,[],<<,}{,0x00,},0x8000,+,"
#define IDX_MEM_ADDR "Pg1,1,==,?{,8,0x90D3,[],<<,}{,0x00,},Pg0,1,==,?{,POP,8,0x90D1,[],<<,},0x8000,+,"
#define STK_ADDR "8,0x90D1,[],<<,0x8000,+,"
#define REG_ADDR "XIO,1,==,?{,0x9100,}{,0x9000,},"
#define INDIR_WR_ADDR "8,0x90D5,[],<<,0x8000,+"
#define INDIR_RD_ADDR "8,0x90D4,[],<<,0x8000,+"

instruction_t instructions [] =
{
  { "ssc",                        "TODO", 15, 1, 0x00, NO_OPER, R_ANAL_OP_TYPE_SWI },
  { "add   A,0x%02x",              "0x%x,A,+=,$c7,CF,=,$z,ZF,=",  4, 2, 0x01, SRC_IMM, R_ANAL_OP_TYPE_ADD },
  { "add   A,[0x%02x]",               "%s0x%x,+,[],A,+=,$c7,CF,=,$z,ZF,=",  6, 2, 0x02, SRC_DIR, R_ANAL_OP_TYPE_ADD },
  { "add   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],A,+=,$c7,CF,=,$z,ZF,=",  7, 2, 0x03, SRC_IDX, R_ANAL_OP_TYPE_ADD },
  { "add   [0x%02x],A",               "A,%s0x%x,+,+=[],$c7,CF,=,$z,ZF,=",  7, 2, 0x04, DST_DIR, R_ANAL_OP_TYPE_ADD },
  { "add   [X+0x%02x],A",             "A,0x%x,X,+,0xff,&,%s+,+=[],$c7,CF,=,$z,ZF,=",  8, 2, 0x05, DST_IDX, R_ANAL_OP_TYPE_ADD },
  { "add   [0x%02x],0x%02x",           "0x%x,%s0x%x,+,+=[],$c7,CF,=,$z,ZF,=",  9, 3, 0x06, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_ADD },
  { "add   [X+0x%02x],0x%02x",         "0x%x,0x%x,X,+,0xff,&,%s+,+=[],$c7,CF,=,$z,ZF,=", 10, 3, 0x07, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_ADD },
  { "push  A",                    "A,8,0x90D1,[],<<,0x8000,+,SP,+,=[],SP,++=",  4, 1, 0x08, NO_OPER, R_ANAL_OP_TYPE_PUSH },

  { "adc   A,0x%02x",              "CF,0x%x,+,A,+=,$c7,CF,=,$z,ZF,=",  4, 2, 0x09, SRC_IMM, R_ANAL_OP_TYPE_ADD },
  { "adc   A,[0x%02x]",               "%s0x%x,+,[],CF,+,A,+=,$c7,CF,=,$z,ZF,=",  6, 2, 0x0a, SRC_DIR, R_ANAL_OP_TYPE_ADD },
  { "adc   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],CF,+,A,+=,$c7,CF,=,$z,ZF,=",  7, 2, 0x0b, SRC_IDX, R_ANAL_OP_TYPE_ADD },
  { "adc   [0x%02x],A",               "CF,A,+,%s0x%x,+,+=[],$c7,CF,=,$z,ZF,=",  7, 2, 0x0c, DST_DIR, R_ANAL_OP_TYPE_ADD },
  { "adc   [X+0x%02x],A",             "CF,A,+,0x%x,X,+,0xff,&,%s+,+=[],$c7,CF,=,$z,ZF,=",  8, 2, 0x0d, DST_IDX, R_ANAL_OP_TYPE_ADD },
  { "adc   [0x%02x],0x%02x",           "CF,0x%x,+,%s0x%x,+,+=[],$c7,CF,=,$z,ZF,=",  9, 3, 0x0e, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_ADD },
  { "adc   [X+0x%02x],0x%02x",         "CF,0x%x,+,0x%x,X,+,0xff,&,%s+,+=[],$c7,CF,=,$z,ZF,=", 10, 3, 0x0f, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_ADD },

  { "push  X",                    "X,8,0x90D1,[],<<,0x8000,+,SP,+,=[],SP,++=",  4, 1, 0x10, NO_OPER, R_ANAL_OP_TYPE_PUSH },
  { "sub   A,0x%02x",              "0x%x,A,-=,$b7,CF,=,$z,ZF,=",  4, 2, 0x11, SRC_IMM, R_ANAL_OP_TYPE_SUB },
  { "sub   A,[0x%02x]",               "%s0x%x,+,[],A,-=,$b7,CF,=,$z,ZF,=",  6, 2, 0x12, SRC_DIR, R_ANAL_OP_TYPE_SUB },
  { "sub   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],A,-=,$b7,CF,=,$z,ZF,=",  7, 2, 0x13, SRC_IDX, R_ANAL_OP_TYPE_SUB },
  { "sub   [0x%02x],A",               "A,%s0x%x,+,-=[],$b7,CF,=,$z,ZF,=",  7, 2, 0x14, DST_DIR, R_ANAL_OP_TYPE_SUB },
  { "sub   [X+0x%02x],A",             "A,0x%x,X,+,0xff,&,%s+,-=[],$b7,CF,=,$z,ZF,=",  8, 2, 0x15, DST_IDX, R_ANAL_OP_TYPE_SUB },
  { "sub   [0x%02x],0x%02x",           "0x%x,%s0x%x,+,-=[],$b7,CF,=,$z,ZF,=",  9, 3, 0x16, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_SUB },
  { "sub   [X+0x%02x],0x%02x",         "0x%x,0x%x,X,+,0xff,&,%s+,-=[],$b7,CF,=,$z,ZF,=", 10, 3, 0x17, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_SUB },

  { "pop   A",                    "SP,--=,8,0x90D1,[],<<,0x8000,+,SP,+,[],A,=,$z,ZF,=",  5, 1, 0x18, NO_OPER, R_ANAL_OP_TYPE_POP },
  { "sbb   A,0x%02x",              "CF,0x%x,+,A,-=,$b7,CF,=,$z,ZF,=",  4, 2, 0x19, SRC_IMM, R_ANAL_OP_TYPE_SUB },
  { "sbb   A,[0x%02x]",               "%s0x%x,+,[],CF,+,A,-=,$b7,CF,=,$z,ZF,=",  6, 2, 0x1a, SRC_DIR, R_ANAL_OP_TYPE_SUB },
  { "sbb   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],CF,+,A,-=,$b7,CF,=,$z,ZF,=",  7, 2, 0x1b, SRC_IDX, R_ANAL_OP_TYPE_SUB },
  { "sbb   [0x%02x],A",               "CF,A,+,%s0x%x,+,-=[],$b7,CF,=,$z,ZF,=",  7, 2, 0x1c, DST_DIR, R_ANAL_OP_TYPE_SUB },
  { "sbb   [X+0x%02x],A",             "CF,A,+,0x%x,X,+,0xff,&,%s+,-=[],$b7,CF,=,$z,ZF,=",  8, 2, 0x1d, DST_IDX, R_ANAL_OP_TYPE_SUB },
  { "sbb   [0x%02x],0x%02x",           "CF,0x%x,+,%s0x%x,+,-=[],$b7,CF,=,$z,ZF,=",  9, 3, 0x1e, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_SUB },
  { "sbb   [X+0x%02x],0x%02x",         "CF,0x%x,+,0x%x,X,+,0xff,&,%s+,-=[],$b7,CF,=,$z,ZF,=", 10, 3, 0x1f, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_SUB },

  { "pop   X",                    "SP,--=,8,0x90D1,[],<<,0x8000,+,SP,+,[],X,=",  5, 1, 0x20, NO_OPER, R_ANAL_OP_TYPE_POP },
  { "and   A,0x%02x",              "0x%x,A,&=,$z,ZF,=",  4, 2, 0x21, SRC_IMM, R_ANAL_OP_TYPE_AND },
  { "and   A,[0x%02x]",               "%s0x%x,+,[],A,&=,$z,ZF,=",  6, 2, 0x22, SRC_DIR, R_ANAL_OP_TYPE_AND },
  { "and   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],A,&=,$z,ZF,=",  7, 2, 0x23, SRC_IDX, R_ANAL_OP_TYPE_AND },
  { "and   [0x%02x],A",               "A,%s0x%x,+,&=[],$z,ZF,=",  7, 2, 0x24, DST_DIR, R_ANAL_OP_TYPE_AND },
  { "and   [X+0x%02x],A",             "A,0x%x,X,+,0xff,&,%s+,&=[],$z,ZF,=",  8, 2, 0x25, DST_IDX, R_ANAL_OP_TYPE_AND },
  { "and   [0x%02x],0x%02x",           "0x%x,%s0x%x,+,&=[],$z,ZF,=",  9, 3, 0x26, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_AND },
  { "and   [X+0x%02x],0x%02x",         "0x%x,0x%x,X,+,0xff,&,%s+,&=[],$z,ZF,=", 10, 3, 0x27, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_AND },

  { "romx",                       "8,A,<<,X,+,[],A,=,$z,ZF,=", 11, 1, 0x28, NO_OPER, R_ANAL_OP_TYPE_SWI },
  { "or    A,0x%02x",              "0x%x,A,|=,$z,ZF,=",  4, 2, 0x29, SRC_IMM, R_ANAL_OP_TYPE_OR },
  { "or    A,[0x%02x]",               "%s0x%x,+,[],A,|=,$z,ZF,=",  6, 2, 0x2a, SRC_DIR, R_ANAL_OP_TYPE_OR },
  { "or    A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],A,|=,$z,ZF,=",  7, 2, 0x2b, SRC_IDX, R_ANAL_OP_TYPE_OR },
  { "or    [0x%02x],A",               "A,%s0x%x,+,|=[],$z,ZF,=",  7, 2, 0x2c, DST_DIR, R_ANAL_OP_TYPE_OR },
  { "or    [X+0x%02x],A",             "A,0x%x,X,+,0xff,&,%s+,|=[],$z,ZF,=",  8, 2, 0x2d, DST_IDX, R_ANAL_OP_TYPE_OR },
  { "or    [0x%02x],0x%02x",           "0x%x,%s0x%x,+,|=[],$z,ZF,=",  9, 3, 0x2e, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_OR },
  { "or    [X+0x%02x],0x%02x",         "0x%x,0x%x,X,+,0xff,&,%s+,|=[],$z,ZF,=", 10, 3, 0x2f, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_OR },

  { "halt",                       "TODO",  9, 1, 0x30, NO_OPER, R_ANAL_OP_TYPE_ILL },
  { "xor   A,0x%02x",              "0x%x,A,^=,$z,ZF,=",  4, 2, 0x31, SRC_IMM, R_ANAL_OP_TYPE_XOR },
  { "xor   A,[0x%02x]",               "%s0x%x,+,[],A,^=,$z,ZF,=",  6, 2, 0x32, SRC_DIR, R_ANAL_OP_TYPE_XOR },
  { "xor   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],A,^=,$z,ZF,=",  7, 2, 0x33, SRC_IDX, R_ANAL_OP_TYPE_XOR },
  { "xor   [0x%02x],A",               "A,%s0x%x,+,^=[],$z,ZF,=",  7, 2, 0x34, DST_DIR, R_ANAL_OP_TYPE_XOR },
  { "xor   [X+0x%02x],A",             "A,0x%x,X,+,0xff,&,%s+,^=[],$z,ZF,=",  8, 2, 0x35, DST_IDX, R_ANAL_OP_TYPE_XOR },
  { "xor   [0x%02x],0x%02x",           "0x%x,%s0x%x,+,^=[],$z,ZF,=",  9, 3, 0x36, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_XOR },
  { "xor   [X+0x%02x],0x%02x",         "0x%x,0x%x,X,+,0xff,&,%s+,^=[],$z,ZF,=", 10, 3, 0x37, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_XOR },

  { "add   SP,0x%02x",             "0x%x,SP,+=",  5, 2, 0x38, SRC_IMM, R_ANAL_OP_TYPE_ADD },
  { "cmp   A,0x%02x",              "%x,A,-,$b,CF,=,$z,ZF,=",  5, 2, 0x39, SRC_IMM, R_ANAL_OP_TYPE_CMP },
  { "cmp   A,[0x%02x]",               "%s0x%x,+,[],A,-,$b,CF,=,$z,ZF,=",  7, 2, 0x3a, SRC_DIR, R_ANAL_OP_TYPE_CMP },
  { "cmp   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],A,-,$b,CF,=,$z,ZF,=",  8, 2, 0x3b, SRC_IDX, R_ANAL_OP_TYPE_CMP },
  { "cmp   [0x%02x],0x%02x",           "%x,%s0x%x,+,[],-,$b,CF,=,$z,ZF,=",  8, 3, 0x3c, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_CMP },
  { "cmp   [X+0x%02x],0x%02x",         "%x,0x%x,X,+,0xff,&,%s+,[],-,$b,CF,=,$z,ZF,=",  9, 3, 0x3d, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_CMP },
  { "mvi   A,[[0x%02x]++]",           "%s0x%x,+,DUP,[],[],A,=,$z,ZF,=,++=[]", 10, 2, 0x3e, SRC_INDPI, R_ANAL_OP_TYPE_MOV },
  { "mvi   [[0x%02x]++],A",           "A,%s0x%x,+,[],=[],%s0x%x,+,++=[]", 10, 2, 0x3f, DST_INDPI, R_ANAL_OP_TYPE_MOV },

  { "nop",                        "",  4, 1, 0x40, NO_OPER, R_ANAL_OP_TYPE_NOP },
  { "and   reg[0x%02x],0x%02x",        "",  9, 3, 0x41, REG_DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_AND },
  { "and   reg[X+0x%02x],0x%02x",      "", 10, 3, 0x42, REG_DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_AND },
  { "or    reg[0x%02x],0x%02x",        "",  9, 3, 0x43, REG_DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_OR },
  { "or    reg[X+0x%02x],0x%02x",      "", 10, 3, 0x44, REG_DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_OR },
  { "xor   reg[0x%02x],0x%02x",        "",  9, 3, 0x45, REG_DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_XOR },
  { "xor   reg[X+0x%02x],0x%02x",      "", 10, 3, 0x46, REG_DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_XOR },
  { "tst   [0x%02x],0x%02x",           "",  7, 3, 0x47, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_ACMP },

  { "tst   [X+0x%02x],0x%02x",         "",  9, 3, 0x48, DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_ACMP },
  { "tst   reg[0x%02x],0x%02x",        "",  9, 3, 0x49, REG_DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_ACMP },
  { "tst   reg[X+0x%02x],0x%02x",      "", 10, 3, 0x4a, REG_DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_ACMP },
  { "swap  A,X",                  "X,NUM,A,A,NUM,X,=,=,$z,ZF,=",  5, 1, 0x4b, NO_OPER, R_ANAL_OP_TYPE_SWITCH },
  { "swap  A,[0x%02x]",               "A,NUM,%s0x%x,+,DUP,[],A,=,$z,ZF,=,=[]",  7, 2, 0x4c, SRC_DIR, R_ANAL_OP_TYPE_SWITCH },
  { "swap  X,[0x%02x]",               "X,NUM,%s0x%x,+,DUP,[],X,=,=[]",  7, 2, 0x4d, SRC_DIR, R_ANAL_OP_TYPE_SWITCH },
  { "swap  A,SP",                 "SP,NUM,A,A,NUM,SP,=,=,$z,ZF,=",  5, 1, 0x4e, NO_OPER, R_ANAL_OP_TYPE_SWITCH },
  { "mov   X,SP",                 "SP,X,=",  4, 1, 0x4f, NO_OPER, R_ANAL_OP_TYPE_MOV },

  { "mov   A,0x%02x",              "0x%x,A,=,$z,ZF,=",  4, 2, 0x50, SRC_IMM, R_ANAL_OP_TYPE_MOV },
  { "mov   A,[0x%02x]",               "%s0x%x,+,[],A,=,$z,ZF,=",  5, 2, 0x51, SRC_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   A,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],A,=,$z,ZF,=",  6, 2, 0x52, SRC_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   [0x%02x],A",               "A,%s0x%x,+,=[]",  5, 2, 0x53, SRC_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   [X+0x%02x],A",             "A,0x%x,X,+,0xff,&,%s+,=[]",  6, 2, 0x54, SRC_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   [0x%02x],0x%02x",           "0x%x,%s0x%x,+,=[]",  8, 3, 0x55, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_MOV },
  { "mov   [X+0x%02x],0x%02x",         "0x%x,0x%x,X,+,0xff,&,%s+,=[]",  9, 3, 0x56, DST_DIR_SRC_IMM, R_ANAL_OP_TYPE_MOV },
  { "mov   X,0x%02x",              "0x%x,X,=",  4, 2, 0x57, SRC_IMM, R_ANAL_OP_TYPE_MOV },

  { "mov   X,[0x%02x]",               "%s0x%x,+,[],X,=",  6, 2, 0x58, SRC_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   X,[X+0x%02x]",             "0x%x,X,+,0xff,&,%s+,[],X,=",  7, 2, 0x59, SRC_IDX, R_ANAL_OP_TYPE_MOV },
  { "mov   [0x%02x],X",               "X,%s0x%x,+,=[]",  5, 2, 0x5a, DST_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   A,X",                  "X,A,=,$z,ZF,=",  4, 1, 0x5b, NO_OPER, R_ANAL_OP_TYPE_MOV },
  { "mov   X,A",                  "A,X,=",  4, 1, 0x5c, NO_OPER, R_ANAL_OP_TYPE_MOV },
  { "mov   A,reg[0x%02x]",            "",  6, 2, 0x5d, REG_SRC_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   A,reg[X+0x%02x]",          "",  7, 2, 0x5e, REG_SRC_IDX, R_ANAL_OP_TYPE_MOV },
  { "mov   [0x%02x],[0x%02x]",            "%s0x%x,+,[],%s0x%x,+,=[]", 10, 3, 0x5f, DST_DIR_SRC_DIR, R_ANAL_OP_TYPE_MOV },

  { "mov   reg[0x%02x],A",            "",  5, 2, 0x60, REG_DST_DIR, R_ANAL_OP_TYPE_MOV },
  { "mov   reg[X+0x%02x],A",          "",  6, 2, 0x61, REG_DST_IDX, R_ANAL_OP_TYPE_MOV },
  { "mov   reg[0x%02x],0x%02x",        "",  8, 3, 0x62, REG_DST_DIR_SRC_IMM_MOV, R_ANAL_OP_TYPE_MOV },
  { "mov   reg[X+0x%02x],0x%02x",      "",  9, 3, 0x63, REG_DST_IDX_SRC_IMM, R_ANAL_OP_TYPE_MOV },
  { "asl   A",                    "1,A,<<=,$c7,CF,=",  4, 1, 0x64, NO_OPER, R_ANAL_OP_TYPE_SAL },
  { "asl   [0x%02x]",                 "1,%s0x%x,+,<<=[],$c7,CF,=",  7, 2, 0x65, SRC_DIR, R_ANAL_OP_TYPE_SAL },
  { "asl   [X+0x%02x]",               "1,0x%x,X,+,0xff,&,%s+,<<=[],$c7,CF,=",  8, 2, 0x66, SRC_IDX, R_ANAL_OP_TYPE_SAL },
  { "asr   A",                    "",  4, 1, 0x67, NO_OPER, R_ANAL_OP_TYPE_SAR },

  { "asr   [0x%02x]",                 "",  7, 2, 0x68, SRC_DIR, R_ANAL_OP_TYPE_SAR },
  { "asr   [X+0x%02x]",               "",  8, 2, 0x69, SRC_IDX, R_ANAL_OP_TYPE_SAR },
  { "rlc   A",                    "",  4, 1, 0x6a, NO_OPER, R_ANAL_OP_TYPE_ROL },
  { "rlc   [0x%02x]",                 "",  7, 2, 0x6b, SRC_DIR, R_ANAL_OP_TYPE_ROL },
  { "rlc   [X+0x%02x]",               "",  8, 2, 0x6c, SRC_IDX, R_ANAL_OP_TYPE_ROL },
  { "rrc   A",                    "",  4, 1, 0x6d, NO_OPER, R_ANAL_OP_TYPE_ROR },
  { "rrc   [0x%02x]",                 "",  7, 2, 0x6e, SRC_DIR, R_ANAL_OP_TYPE_ROR },
  { "rrc   [X+0x%02x]",               "",  8, 2, 0x6f, SRC_IDX, R_ANAL_OP_TYPE_ROR },

  { "and   F,0x%02x",              "0x%x,CPU_F,&=",  4, 2, 0x70, PSW_AND, R_ANAL_OP_TYPE_AND },
  { "or    F,0x%02x",              "0x%x,CPU_F,~=",  4, 2, 0x71, PSW_OR, R_ANAL_OP_TYPE_OR },
  { "xor   F,0x%02x",              "0x%x,CPU_F,^=",  4, 2, 0x72, PSW_XOR, R_ANAL_OP_TYPE_XOR },
  { "cpl   A",                    "0xff,A,^=,$z,ZF,=",  4, 1, 0x73, NO_OPER, R_ANAL_OP_TYPE_CPL },
  { "inc   A",                    "A,++=,$z,ZF,=,$c,CF,=",  4, 1, 0x74, NO_OPER, R_ANAL_OP_TYPE_ADD },
  { "inc   X",                    "X,++=,$z,ZF,=,$c,CF,=",  4, 1, 0x75, NO_OPER, R_ANAL_OP_TYPE_ADD },
  { "inc   [0x%02x]",                 "%s0x%x,++=[],$z,ZF,=,$c,CF,=",  7, 2, 0x76, SRC_DIR, R_ANAL_OP_TYPE_ADD },
  { "inc   [X+0x%02x]",               "0x%x,X,+,0xff,&,%s+,++=[],$z,ZF,=,$c,CF,=",  8, 2, 0x77, SRC_DIR, R_ANAL_OP_TYPE_ADD },

  { "dec   A",                    "A,--=,$z,ZF,=,$b1,CF,=",  4, 1, 0x78, NO_OPER, R_ANAL_OP_TYPE_SUB },
  { "dec   X",                    "X,--=,$z,ZF,=,$b1,CF,=",  4, 1, 0x79, NO_OPER, R_ANAL_OP_TYPE_SUB },
  { "dec   [0x%02x]",                 "%s0x%x,--=[],$z,ZF,=,$b1,CF,=",  7, 2, 0x7a, SRC_DIR, R_ANAL_OP_TYPE_SUB },
  { "dec   [X+0x%02x]",               "0x%x,X,+,0xff,&,%s+,--=[],$z,ZF,=,$b1,CF,=",  8, 2, 0x7b, SRC_IDX, R_ANAL_OP_TYPE_SUB },
  { "lcall 0x%04x",                   "pch,8,0x90D1,[],<<,0x8000,+,SP,+,=[],SP,++=,pcl,8,0x90D1,[],<<,0x8000,+,SP,+,=[],SP,++=,%x,PC,=", 13, 3, 0x7c, ABS16, R_ANAL_OP_TYPE_CALL },
  { "ljmp  0x%04x",                   "0x%x,PC,=",  7, 3, 0x7d, ABS16, R_ANAL_OP_TYPE_JMP },
  { "reti",                       "SP,--=,8,0x90D1,[],<<,0x8000,+,SP,+,[],CPU_F,=,SP,--=,8,0x90D1,[],<<,0x8000,+,SP,+,[],pcl,=,SP,--=,8,0x90D1,[],<<,0x8000,+,SP,+,[],pch,=", 10, 1, 0x7e, RET, R_ANAL_OP_TYPE_RET },
  { "ret",                        "SP,--=,8,0x90D1,[],<<,0x8000,+,SP,+,[],pcl,=,SP,--=,8,0x90D1,[],<<,0x8000,+,SP,+,[],pch,=",  8, 1, 0x7f, RET, R_ANAL_OP_TYPE_RET },

  { "jmp   0x%04x",                   "%d,PC,+=",  5, 2, 0x80, REL12, R_ANAL_OP_TYPE_JMP },
  { "call  0x%04x",                   "pch,8,0x90D1,[],<<,0x8000,+,SP,+,=[],SP,++=,pcl,8,0x90D1,[],<<,0x8000,+,SP,+,=[],SP,++=,%x,PC,+=", 11, 2, 0x90, REL12_CALL, R_ANAL_OP_TYPE_CALL },
  { "jz    0x%04x",                   "ZF,?{,%d,PC,+=,}",  5, 2, 0xa0, REL12, R_ANAL_OP_TYPE_CJMP },
  { "jnz   0x%04x",                   "ZF,!,?{,%d,PC,+=,}",  5, 2, 0xb0, REL12, R_ANAL_OP_TYPE_CJMP },
  { "jc    0x%04x",                   "CF,?{,%d,PC,+=,}",  5, 2, 0xc0, REL12, R_ANAL_OP_TYPE_CJMP },
  { "jnc   0x%04x",                   "CF,!,?{,%d,PC,+=,}",  5, 2, 0xd0, REL12, R_ANAL_OP_TYPE_CJMP },
  { "jacc  A+0x%04x",                 "%d,A,+,0xff,&,PC,+=",  7, 2, 0xe0, REL12, R_ANAL_OP_TYPE_CJMP },
  { "index 0x%04x",                   "", 13, 2, 0xf0, REL12, R_ANAL_OP_TYPE_MOV },
};

#endif /*  M8CASM_H */
