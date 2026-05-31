# core Phoenix-RTOS LwIP port sources
NAME := lwip
LOCAL_PATH := $(call my-dir)
SRCS := $(wildcard $(LOCAL_PATH)*.c)
DEP_LIBS := lwip-drivers lwip-core


ifeq ($(LWIP_G3_BUILD), yes)
LIBS := ps_eap ps_g3_sap libtinyaes hal
endif


# FIXME: use constructors for registration in lwip
LOCAL_CFLAGS := $(addprefix -DHAVE_DRIVER_,$(sort $(NET_DRIVERS)))

ifeq (${LWIP_IPSEC_BUILD},yes)
  LOCAL_CFLAGS += -DLWIP_IPSEC=1 -DLWIP_IPSEC_DEV=\"${LWIP_IPSEC_DEV}\"
  DEP_LIBS += lwip-ipsec
else
  LOCAL_CFLAGS += -DLWIP_IPSEC=0
endif

ifeq (${LWIP_WIFI_BUILD},yes)
  LOCAL_CFLAGS += -DLWIP_WIFI=1
  DEP_LIBS += wifi-hal wifi-lwip wifi-whd
else
  LOCAL_CFLAGS += -DLWIP_WIFI=0
endif

LWIP_MAIN_THREAD_STACKSIZE ?= 4096
LOCAL_LDFLAGS := -z stack-size=$(LWIP_MAIN_THREAD_STACKSIZE)

# Pi 4 PoC (2026-05-28): host the Phoenix-RTOS USB host stack INSIDE this
# lwip-port process. On BCM2711 the usb daemon's own xHCI inbound DMA
# writes are silently lost (a per-process effect we couldn't root-cause)
# while a separate process drives the same controller fine — proven by
# the diag-udp 'X' rig in this binary. The user-chosen PoC is to run the
# real usb stack (libusb + xhci HCD + hub/HID/usbkbd drivers) in this
# process to confirm a working USB keyboard can be enumerated.
#
# The 6 thin shim files in port/usb-embed/ each #include the corresponding
# source from phoenix-rtos-usb/usb/ — they give the embedded build its own
# .o paths so Phoenix's source-path-keyed object cache doesn't reuse the
# usb daemon's .o (which has main()). USB_NO_MAIN excludes main() from
# the embedded usb.c; usb_init() is the entry point lwip-port will call.
ifeq ($(PCI_EXPRESS_BCM2711_INDEXED_CFG),y)
  USB_HOST_INCLUDE := $(LOCAL_PATH)../../phoenix-rtos-usb/usb
  SRCS += $(addprefix $(LOCAL_PATH)usb-embed/,usb.c dev.c drv.c hcd.c hub.c mem.c)
  LOCAL_CFLAGS += -DUSB_NO_MAIN -DLWIP_EMBED_USB -I$(USB_HOST_INCLUDE)
  LIBS += libusbxhci libusbdrv-usbkbd libusbdrv-usbmouse libusb
endif

include $(binary.mk)
