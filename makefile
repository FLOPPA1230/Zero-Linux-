CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wcast-qual \
            -Wwrite-strings -Wpointer-arith -Wstrict-prototypes \
            -Wmissing-prototypes -Wno-unused-parameter -pthread
LDFLAGS  ?= -pthread
LDLIBS   ?= 
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
OBJDIR   ?= build

TARGET   := lz
SRCS     := src/main.c \
            src/utils/logger.c \
            src/utils/config.c \
            src/core/ringbuf.c \
            src/core/isolation.c \
            src/core/replay.c \
            src/telemetry/pmc.c \
            src/telemetry/intel_pt.c \
            src/telemetry/msr_filter.c \
            src/channel/ebpf.c \
            src/analysis/decode.c \
            src/analysis/report.c

OBJS     := $(patsubst src/%.c, $(OBJDIR)/%.o, $(SRCS))
DEPS     := $(OBJS:.o=.d)

.PHONY: all clean install uninstall dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJDIR)/utils
	@mkdir -p $(OBJDIR)/core
	@mkdir -p $(OBJDIR)/telemetry
	@mkdir -p $(OBJDIR)/channel
	@mkdir -p $(OBJDIR)/analysis

$(TARGET): $(OBJS)
	@$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o: src/%.c include/lz.h | dirs
	@$(CC) $(CFLAGS) -Iinclude -MMD -MP -c $< -o $@

-include $(DEPS)

clean:
	@rm -rf $(OBJDIR) $(TARGET) lz_report

install: all
	@install -d $(DESTDIR)$(BINDIR)
	@install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	@rm -f $(DESTDIR)$(BINDIR)/$(TARGET)