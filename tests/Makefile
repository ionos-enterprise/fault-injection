#
# Copyright Profitbricks GmbH - All rights reserved
#

# Called as kbuild
ifneq ($(KERNELRELEASE),)

# We are not a part of the kernel, thus build always as a module
obj-m := test_fault_inject.o

KBUILD_EXTRA_SYMBOLS := $(src)/../Module.symvers

# Normal Makefile, redirect to kbuild
else

KDIR       ?= /usr/src/linux
ROOT_DIR   := $(PWD)

default::
	@$(MAKE) -C $(KDIR) M=$(ROOT_DIR) $(MAKEFLAGS)

clean::
	@$(MAKE) -C $(KDIR) M=$(ROOT_DIR) $(MAKEFLAGS) clean

install:: default

# By default modules_install does not build anything. That's odd.
# So not to break previous behavior I simply call modules build before
# installing them.
modules_install:: default
	@$(MAKE) -C $(KDIR) M=$(ROOT_DIR) $(MAKEFLAGS) modules_install

endif
