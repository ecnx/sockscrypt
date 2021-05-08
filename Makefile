# SocksCrypt Makefile
INCLUDES=-I include -DAESKEY=$(AESKEY)
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss

OBJS = \
	bin/startup.o \
	bin/proxy.o \
	bin/crypto.o \

all: host

internal: prepare
	@echo "  CC    src/startup.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/startup.c -o bin/startup.o
	@echo "  CC    src/proxy.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/proxy.c -o bin/proxy.o
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
		CFLAGS='-c -Wall -Wextra -O3 -ffunction-sections -fdata-sections -Wstrict-prototypes -DVERBOSE_MODE' \
		LDFLAGS='-Wl,--gc-sections -Wl,--relax'

nodaemon:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -O2 -ffunction-sections -fdata-sections -Wstrict-prototypes -DNO_DAEMON' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax'

arm:
	@make internal \
		CC=arm-linux-gnueabi-gcc \
		LD=arm-linux-gnueabi-gcc \
		CFLAGS='-c $(ARM_CFLAGS) -I $(ESLIB_INC) -O2 -DSILENT_MODE' \
		LDFLAGS='$(ARM_LDFLAGS) -L $(ESLIB_DIR) -les-arm'

post:
	@echo "  STRIP sockscrypt"
	@sstrip bin/sockscrypt
	@echo "  UPX   sockscrypt"
	@upx bin/sockscrypt
	@echo "  LCK   sockscrypt"
	@perl -pi -e 's/UPX!/EsNf/g' bin/sockscrypt
	@echo "  AEM   sockscrypt"
	@nogdb bin/sockscrypt

update:
	@cp -v /tmp/mbedtls/include/mbedtls/aes.h include/mbedtls/aes.h
	@cp -v /tmp/mbedtls/include/mbedtls/error.h include/mbedtls/error.h
	@cp -v /tmp/mbedtls/library/aes.c lib/aes.c
	@cp -v /tmp/mbedtls/library/aesni.h lib/aesni.h
	@cp -v /tmp/mbedtls/library/aesni.c lib/aesni.c
	@cp -v /tmp/mbedtls/library/padlock.h lib/padlock.h

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

gendoc:
	@doxygen aux/doxygen.conf
