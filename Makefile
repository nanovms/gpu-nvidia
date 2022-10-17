###########################################################################
# This is the top level makefile for the NVIDIA Nanos klib source package.
#
# To build: run `make NANOS_DIR=/path/to/nanos/kernel/source`
###########################################################################

ifeq ($(NANOS_DIR),)
$(error NANOS_DIR must be set to the absolute path of the Nanos kernel source folder)
endif

TARGET_ARCH ?= x86_64
OUTPUTDIR ?= _out/Nanos_$(TARGET_ARCH)

all: gpu_nvidia

nv_kernel_o                = src/nvidia/$(OUTPUTDIR)/nv-kernel.o

.PHONY: $(nv_kernel_o)


###########################################################################
# nv-kernel.o is the OS agnostic portion of nvidia.ko
###########################################################################

$(nv_kernel_o):
	$(MAKE) -C src/nvidia


###########################################################################
# After the OS agnostic portions are built, descend into kernel-open/ and build
# the kernel modules with kbuild.
###########################################################################

gpu_nvidia: $(nv_kernel_o)
	$(MAKE) -C kernel-open $(OUTPUTDIR)/gpu_nvidia


###########################################################################
# clean
###########################################################################

.PHONY: clean nvidia.clean kernel-open.clean

clean: nvidia.clean kernel-open.clean

nvidia.clean:
	$(MAKE) -C src/nvidia clean

kernel-open.clean:
	$(MAKE) -C kernel-open clean
