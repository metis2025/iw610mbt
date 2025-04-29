#
# Macro for NDK path
NDK_PATH := /usr/local/arm/android-ndk-r23-beta5

# Declare Variables
OSTYPE := android
CC := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
BUILD_SUFFIX := _imx_android
SRCDIR := ../src
OBJDIR := build$(BUILD_SUFFIX)
BT_APP := btapp$(BUILD_SUFFIX)

# Compiler and linker flags
CFLAGS=-g -O2 -Wall -I$(SRCDIR)
DEPFLAGS=-MT $@ -MMD -MP -MF $(OBJDIR)/$*.d

# List of object files for BT_APP
BT_APP_OBJS=bt_main

# Targets
.PHONY: all clean help

all: $(BT_APP)

# Rule to compile Object file
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) -c $< -o $@
$(OBJDIR)/%.d: $(OBJDIR)/%.o

# Rule to create build directory.
$(OBJDIR):
	mkdir -p $(OBJDIR)

#Convert source files to correspoding object files in OBJDIR
BT_APP_OBJS := $(addprefix $(OBJDIR)/, $(BT_APP_OBJS))
BT_APP_OBJS := $(addsuffix .o, $(BT_APP_OBJS))

#Target to build BT_APP binary
$(BT_APP): $(BT_APP_OBJS)
	$(CC) $(LFLAGS) $(BT_APP_OBJS) $(LDLIBS) -o $@

#Target Depedancies
$(BT_APP_OBJS): | $(OBJDIR)
$(BT_APP): $(BT_APP_OBJS) Makefile

clean:
	rm -f $(BT_APP)
	rm -rf $(OBJDIR)
	@echo "BT_APP_OBJS:       $(BT_APP_OBJS)"

help:
	@echo "Compilation for Imx:android"
	@echo "make clean all"
	@echo ".$(CC)"
