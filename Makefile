# Makefile for rm-webshot
#
# Common targets:
#   make            build the binary into ./rm-webshot
#   make debug      rebuild with debug symbols and sanitizers
#   make clean      remove build artifacts
#   make install    copy the binary to $(PREFIX)/bin (default /usr/local/bin)
#
# The scanner needs nothing beyond libc and pthreads, so there are no -l flags
# for third party libraries. A headless browser is a run time dependency only.

CC      ?= cc
PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin

# -D_GNU_SOURCE exposes the POSIX and GNU functions we rely on (strtok_r,
# nftw, MSG_NOSIGNAL and friends) while still compiling as standard C11.
# It works on glibc and musl alike.
CFLAGS  ?= -O2
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wshadow -Wformat=2 -pedantic
LDFLAGS +=
LDLIBS  += -pthread

TARGET  = rm-webshot
SRCDIR  = src
OBJDIR  = build

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
DEPS    = $(OBJECTS:.o=.d)

.PHONY: all clean debug install uninstall

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# -MMD -MP generate header dependency files so touching a .h rebuilds the
# translation units that include it.
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

# Address and undefined behaviour sanitizers, useful when editing the code.
debug: CFLAGS := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wshadow -Wformat=2 -pedantic \
                 -g -O0 -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -rf $(OBJDIR) $(TARGET)

-include $(DEPS)
