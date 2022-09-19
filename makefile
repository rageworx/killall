# MSYS2 killall emulation source,

GPP = g++
CFLAGS = -s -O2
LFLAGS = -static
SRC = src/main.cpp
DST = killall

all: prepare bin/${DST}

prepare:
	@mkdir -p bin

clean:
	@rm -rf ${DST}

bin/${DST}: ${SRC}
	@${GPP} ${CFLAGS} $< ${LFLAGS} -o $@

install: bin/${DST}
	@cp -rf $< /usr/local/bin

uninstall: /usr/local/bin/${DST}
	@rm -rf $<
