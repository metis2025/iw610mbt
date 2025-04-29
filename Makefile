# File: Makefile
# Copyright 2014-2023 NXP
#

CC ?=		$(CROSS_COMPILE)gcc
LD ?=		$(CROSS_COMPILE)ld

BACKUP=		/root/backup
YMD=		`date +%Y%m%d%H%M`

#############################################################################
# Configuration Options
#############################################################################

# Debug Option
# DEBUG LEVEL n/1/2:
# n: NO DEBUG
# 1: PRINTM(MSG,...), PRINTM(FATAL,...), PRINTM(WARN,...) and PRINTM(INFO,...)
# 2: All PRINTM()
CONFIG_DEBUG=1




#############################################################################
# Multi-chip sets
#############################################################################
CONFIG_USB8897=n
CONFIG_USB8997=n
CONFIG_USB8978=n
CONFIG_USB9097=n
CONFIG_USBIW610=y
CONFIG_USBIW624=n
CONFIG_USB9098=n

#############################################################################
# Select Platform Tools
#############################################################################

MODEXT = ko


ifeq ($(CONFIG_64BIT), y)
	EXTRA_CFLAGS += -DMBT_64BIT
endif

ifeq ($(CONFIG_T50), y)
        EXTRA_CFLAGS += -DT50
        EXTRA_CFLAGS += -DT40
        EXTRA_CFLAGS += -DT3T
endif

ifeq ($(CONFIG_BLE_WAKEUP), y)
        EXTRA_CFLAGS += -DBLE_WAKEUP
endif
ifeq ($(CONFIG_USB8897), y)
	CONFIG_MUSB=y
	EXTRA_CFLAGS += -DUSB8897
endif
ifeq ($(CONFIG_USB8997), y)
	CONFIG_MUSB=y
	EXTRA_CFLAGS += -DUSB8997
endif
ifeq ($(CONFIG_USB8978), y)
	CONFIG_MUSB=y
	EXTRA_CFLAGS += -DUSB8978
endif
ifeq ($(CONFIG_USB9097), y)
	CONFIG_MUSB=y
	EXTRA_CFLAGS += -DUSB9097
endif
ifeq ($(CONFIG_USBIW610), y)
	CONFIG_MUSB=y
	EXTRA_CFLAGS += -DUSBIW610
endif
ifeq ($(CONFIG_USBIW624), y)
	CONFIG_MUSB=y
	EXTRA_CFLAGS += -DUSBIW624
endif

ifeq ($(CONFIG_USB9098), y)
	CONFIG_MUSB=y
	EXTRA_CFLAGS += -DUSB9098
endif
ifeq ($(CONFIG_MUSB), y)
	EXTRA_CFLAGS += -DUSB
	EXTRA_CFLAGS += -DUSB_SCO_SUPPORT
endif





#ifdef KMINORVER_6_1_36_AT
KERNELDIR ?= /usr/src/arm/androidT_kernel/kernel_imx_6_1_36
CROSS_COMPILE ?= aarch64-linux-gnu-
#endif



KERNELVERSION_X86 := 	$(shell uname -r)
KERNELDIR?=/lib/modules/$(KERNELVERSION_X86)/build


EXTRA_CFLAGS += -I$(M)/bt
LD += -S

BINDIR = ../bin_bt

#############################################################################
# Compiler Flags
#############################################################################
	EXTRA_CFLAGS += -DFPNUM='"99"'

ifeq ($(CONFIG_DEBUG),1)
	EXTRA_CFLAGS += -DDEBUG_LEVEL1
endif

ifeq ($(CONFIG_DEBUG),2)
	EXTRA_CFLAGS += -DDEBUG_LEVEL1
	EXTRA_CFLAGS += -DDEBUG_LEVEL2
	DBG=	-dbg
endif


#############################################################################
# Make Targets
#############################################################################

ifneq ($(KERNELRELEASE),)

	BTOBJS = bt/bt_main.o bt/bt_proc.o bt/mbt_char.o
ifeq ($(CONFIG_MUSB), y)
	BTOBJS += bt/bt_usb.o
endif

BTOBJS += bt/bt_init.o

obj-m := btxxx.o
btxxx-objs := $(BTOBJS)


# Otherwise we were called directly from the command line; invoke the kernel build system.
else
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) modules
endif

###############################################################

export		CC LD EXTRA_CFLAGS KERNELDIR

#.PHONY: app/fm_app clean distclean
#.PHONY: app/btapp clean distclean

#app/fm_app:
# Commenting btapp compilation from this Makefile, as it will be built indepedantly
# Current directory structure of btapp is as follows.
# app/btapp
#     |-----> src     #Moved bt_main.c bt.h here
#     |-----> android #Android Toolchain Specific Makfile
#     |-----> linux   #i.MX Linux/U16 makefile
#app/btapp:
#	$(MAKE) -C $@

echo:

build:		echo default

	@if [ ! -d $(BINDIR) ]; then \
		mkdir $(BINDIR); \
	fi

	cp -f config/bt_mod_para.conf $(BINDIR)/
	cp -f btxxx.$(MODEXT) $(BINDIR)/bt$(DBG).$(MODEXT)


	cp -f README $(BINDIR)

#	$(MAKE) -C app/fm_app $@ INSTALLDIR=$(BINDIR);
#	$(MAKE) -C app/btapp $@ INSTALLDIR=$(BINDIR);
#	cp -f app/fm_app/fmapp $(BINDIR);
#	cp -f app/btapp/btapp $(BINDIR);

clean:
	-find . -name "*.o" -exec rm {} \;
	-find . -name "*.ko" -exec rm {} \;
	-find . -name ".*.cmd" -exec rm {} \;
	-find . -name "*.mod.c" -exec rm {} \;
	-find . -name "*.symvers" -exec rm {} \;
	-find . -name "modules.order" -exec rm {} \;
	-find . -name ".*.dwo" -exec rm {} \;
	-find . -name "*dwo" -exec rm {} \;
	-rm -rf .tmp_versions
#	$(MAKE) -C app/fm_app $@
#	$(MAKE) -C app/btapp $@

install: default

distclean:
	-find . -name "*.o" -exec rm {} \;
	-find . -name "*.orig" -exec rm {} \;
	-find . -name "*.swp" -exec rm {} \;
	-find . -name "*.*~" -exec rm {} \;
	-find . -name "*~" -exec rm {} \;
	-find . -name "*.d" -exec rm {} \;
	-find . -name "*.a" -exec rm {} \;
	-find . -name "tags" -exec rm {} \;
	-find . -name ".*" -exec rm -rf 2> /dev/null \;
	-find . -name "*.ko" -exec rm {} \;
	-find . -name ".*.cmd" -exec rm {} \;
	-find . -name "*.mod.c" -exec rm {} \;
	-find . -name ".*.dwo" -exec rm {} \;
	-find . -name "*dwo" -exec rm {} \;
	-rm -rf .tmp_versions
#	$(MAKE) -C app/fm_app $@
#	$(MAKE) -C app/btapp $@
# End of file;
