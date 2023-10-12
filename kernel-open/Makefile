#
# This Makefile was automatically generated; do not edit.
#

###########################################################################
# Makefile for NVIDIA Nanos GPU driver klib
###########################################################################

TARGET_ARCH ?= x86_64
OUTPUTDIR ?= _out/Nanos_$(TARGET_ARCH)

include $(NANOS_DIR)/rules.mk

GENHEADERS=	$(CURDIR)/closure_templates.h

include nvidia/nvidia-sources.Kbuild
NVIDIA_OBJS=	$(addprefix $(OUTPUTDIR)/, $(NVIDIA_SOURCES:c=o))
NVIDIA_DEPS=	$(addprefix $(OUTPUTDIR)/, $(NVIDIA_SOURCES:c=d))

include nvidia-uvm/nvidia-uvm-sources.Kbuild
NVIDIA_UVM_OBJS=	$(addprefix $(OUTPUTDIR)/, $(NVIDIA_UVM_SOURCES:c=o))
NVIDIA_UVM_DEPS=	$(addprefix $(OUTPUTDIR)/, $(NVIDIA_UVM_SOURCES:c=d))

OBJS=	$(NVIDIA_OBJS) $(NVIDIA_UVM_OBJS)
DEPS=	$(NVIDIA_DEPS) $(NVIDIA_UVM_DEPS)

OBJDIR = $(OUTPUTDIR)
CLEANFILES = $(GENHEADERS) $(OBJS) $(DEPS) \
	$(OUTPUTDIR)/gpu_nvidia $(OUTPUTDIR)/gpu_nvidia.dbg
CLEANDIRS = $(OBJDIR)/nvidia $(OBJDIR)/nvidia-uvm

$(OUTPUTDIR)/nvidia/%.o: nvidia/%.c | $(sort $(GENHEADERS))
	@$(MKDIR) $(dir $@)
	$(call cmd,cc)

$(OUTPUTDIR)/nvidia-uvm/%.o: INCLUDES += -Invidia-uvm
$(OUTPUTDIR)/nvidia-uvm/%.o: CFLAGS += -DNVIDIA_UVM_ENABLED

$(OUTPUTDIR)/nvidia-uvm/%.o: nvidia-uvm/%.c | $(sort $(GENHEADERS))
	@$(MKDIR) $(dir $@)
	$(call cmd,cc)

$(OUTPUTDIR)/gpu_nvidia.dbg: $(OBJS) ../src/nvidia/$(OUTPUTDIR)/nv-kernel.o
	$(call cmd,ld)

$(OUTPUTDIR)/gpu_nvidia: $(OUTPUTDIR)/gpu_nvidia.dbg
	$(call cmd,strip)

-include $(sort $(DEPS))

ifeq ($(UNAME_s),Darwin)
ELF_TARGET=     -target x86_64-elf
CFLAGS+=        $(ELF_TARGET)
LD=             x86_64-elf-ld
OBJDUMP=        x86_64-elf-objdump
else
LD=             $(CROSS_COMPILE)ld
endif

DEFINES=	-DKERNEL -DKLIB

ifneq ($(NOSMP),)
DEFINES+=	-DSPIN_LOCK_DEBUG_NOSMP
else
DEFINES+=	-DSMP_ENABLE
endif

INCLUDES= \
	-I. \
	-I$(ARCHDIR) \
	-I$(SRCDIR) \
	-I$(OUTDIR) \
	-I$(SRCDIR)/kernel \
	-I$(SRCDIR)/net \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/unix \
	-I$(SRCDIR)/fs \
	-Icommon/inc \
	-I ../src/nvidia/src/libraries/libspdm/2.3.1/include \

CFLAGS+=	$(KERNCFLAGS) -O3 $(INCLUDES) -fPIC $(DEFINES)

LDFLAGS+=	-shared -Bsymbolic -nostdlib -T$(ARCHDIR)/klib.lds

STRIPFLAGS=	-g

CFLAGS+=	-D__KERNEL__ -DMODULE -DNVRM -DNV_UVM_ENABLE
CFLAGS+=	-DNV_VERSION_STRING=\"535.113.01\"
CFLAGS+=	-Wno-unused-function
