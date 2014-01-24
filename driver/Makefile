ifeq ($(KERNELRELEASE),)

	KVERSION ?= $(shell uname -r)

	BUILD_DIR ?= /lib/modules/${KVERSION}/build

	PWD := $(shell pwd)

modules:
	$(MAKE) -C $(BUILD_DIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(BUILD_DIR) M=$(PWD) modules_install

clean:
	rm -rf *~ *.o .*.cmd *.mod.c *.ko *.ko.unsigned .depend \
	.tmp_versions modules.order Module.symvers Module.markers

.PHONY: modules modules_install clean

else

# Called from kernel build system -- just declare the module(s).

obj-m := pib.o
pib-y := pib_main.o pib_dma.o pib_lib.o \
	pib_ucontext.o pib_pd.o pib_qp.o pib_multicast.o pib_cq.o pib_srq.o pib_ah.o pib_mr.o \
	pib_mad.o pib_mad_pma.o pib_easy_sw.o \
	pib_thread.o pib_ud.o pib_rc.o

endif
