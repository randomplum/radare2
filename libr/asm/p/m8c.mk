OBJ_M8C=asm_m8c.o

STATIC_OBJ+=${OBJ_M8C}
TARGET_M8C=asm_m8c.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_M8C}

${TARGET_M8C}: ${OBJ_M8C}
	${CC} $(call libname,asm_m8c) ${LDFLAGS} ${CFLAGS} -o ${TARGET_M8C} ${OBJ_M8C}
endif
