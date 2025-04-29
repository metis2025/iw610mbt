#
# Tools makefile for Linux

OSTYPE=linux
CC?=gcc

ifeq ($(ARCH),arm64)
	BUILD_SUFFIX=_imx_lnx
else
	BUILD_SUFFIX=_linux
endif

SRCDIR=../src

OBJDIR=build$(BUILD_SUFFIX)

BT_APP=btapp$(BUILD_SUFFIX)

CFLAGS=-g -O2 -Wall -I$(SRCDIR)

DEPFLAGS=-MT $@ -MMD -MP -MF $(OBJDIR)/$*.d

LDLIBS+=-lrt

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.d: $(OBJDIR)/%.o

$(OBJDIR):
	mkdir -p $(OBJDIR)


BT_APP_OBJS=bt_main

BT_APP_OBJS := $(addprefix $(OBJDIR)/, $(BT_APP_OBJS))
BT_APP_OBJS := $(addsuffix .o, $(BT_APP_OBJS))


$(BT_APP): $(BT_APP_OBJS)
	$(CC) $(LFLAGS) $(BT_APP_OBJS) $(LDLIBS) -o $@

$(BT_APP_OBJS): | $(OBJDIR)

$(BT_APP): $(BT_APP_OBJS) Makefile

.PHONY: help
help:
	@echo "Compilation for Linux:"
	@echo "    make clean all"
	@echo "Compilation for Imx:"
	@echo ". /opt/fsl-imx-xwayland/5.10-hardknott/environment-setup-cortexa53-crypto-poky-linux"
	@echo "    make clean all"


.PHONY: clean
clean:
	rm -f $(BT_APP)
	rm -rf $(OBJDIR)
	@echo "BT_APP_OBJS:       $(BT_APP_OBJS)"

.PHONY: all
all: $(BT_APP)


