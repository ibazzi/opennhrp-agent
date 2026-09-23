CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -Os -pipe
LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto -lpthread

CPPFLAGS += -Isrc
CFLAGS += -std=c11 -Wall -Wextra -Werror

BIN := build/opennhrp-agent
SRC := src/opennhrp-agent.c

.PHONY: all clean deb install test

all: $(BIN)

$(BIN): $(SRC) src/jsmn.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LDLIBS)

test: $(BIN)
	$(BIN) --self-test
	python3 tests/parity.py $(BIN)

install: $(BIN)
	install -D -m 0755 $(BIN) $(DESTDIR)/usr/sbin/opennhrp-agent

deb:
	rm -rf build/src
	mkdir -p build/src
	find . -maxdepth 1 ! -name '.' ! -name 'build' ! -name '.git' -exec cp -a {} build/src/ \;
	cd build/src && dpkg-buildpackage -b -us -uc
	rm -rf build/src

clean:
	rm -f $(BIN)
