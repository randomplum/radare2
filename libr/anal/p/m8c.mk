OBJ_M8C=anal_m8c.o
CFLAGS+=-I../asm/arch/m8c/

STATIC_OBJ+=${OBJ_M8C}
TARGET_M8C=anal_m8c.${EXT_SO}

ALL_TARGETS+=${TARGET_M8C}

${TARGET_M8C}: ${OBJ_M8C}
	${CC} $(call libname,anal_m8c) ${LDFLAGS} ${CFLAGS} \
		-o anal_m8c.${EXT_SO} ${OBJ_M8C}
