# SocksCrypt Makefile
INCLUDES=-I include 
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss

OBJS = \
	bin/startup.o \
	bin/proxy.o \
	bin/util.o \
	bin/crypto.o

all: host

up:
	@cp -pv ../proxy-util/util.h include/util.h
	@cp -pv ../proxy-util/util.c src/util.c

internal: prepare
	@echo "  CC    src/startup.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/startup.c -o bin/startup.o
	@echo "  CC    src/proxy.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/proxy.c -o bin/proxy.o
	@echo "  CC    src/util.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/util.c -o bin/util.o
	@echo "  CC    src/crypto.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/crypto.c -o bin/crypto.o
	@echo "  LD    bin/sockscrypt"
	@$(LD) -o bin/sockscrypt $(OBJS) $(LDFLAGS) -lmbedcrypto

prepare:
	@mkdir -p bin

host:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -O2 -ffunction-sections -fdata-sections -Wstrict-prototypes' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax'

arm:
	@make internal \
		CC=arm-linux-gnueabi-gcc \
		LD=arm-linux-gnueabi-gcc \
		CFLAGS='-c $(ARM_CFLAGS) -I $(ESLIB_INC) -O2' \
		LDFLAGS='$(ARM_LDFLAGS) -L $(ESLIB_DIR) -les-arm'

indent:
	@indent $(INDENT_FLAGS) ./*/*.h
	@indent $(INDENT_FLAGS) ./*/*.c
	@rm -rf ./*/*~

clean:
	@echo "  CLEAN ."
	@rm -rf bin

analysis:
	@scan-build make
	@cppcheck --force */*.h
	@cppcheck --force */*.c
