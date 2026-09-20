#
# Makefile for Phoenix-RTOS USB host
#
# Copyright 2021 Phoenix Systems
#

NAME := usb
LOCAL_SRCS := usb.c dev.c drv.c hcd.c hub.c mem.c
LOCAL_HEADERS := hcd.h hub.h dev.h drv.h usbhost.h
# USB_HOSTDRV_DEP_LIBS: libraries a hosted driver needs but that are not USB
# drivers themselves. It must come AFTER USB_HOSTDRV_LIBS -- static archives
# resolve left to right, so a driver's dependency has to follow the driver.
#
# Added for umass, which links libext2 when built with UMASS_MOUNT_EXT2. That
# lib is declared in the umass Makefile, but only for the STANDALONE umass
# binary; the libusbdrv-umass.a hosted here carries the references and nothing
# resolved them, so the daemon failed to link with undefined libext2_mount /
# libext2_unmount / libext2_handler.
LIBS := $(USB_HCD_LIBS) $(USB_HOSTDRV_LIBS) $(USB_HOSTDRV_DEP_LIBS) libusb
DEPS := libusb

ifneq ($(USB_HOSTDRV_LIBS),)
 CFLAGS += -DUSB_INTERNAL_ONLY
endif

include $(binary.mk)
