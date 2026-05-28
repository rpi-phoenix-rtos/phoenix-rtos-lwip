/* Shim: pull the Phoenix-RTOS USB host stack into the lwip-port binary.
 *
 * On the Pi 4 (BCM2711) the usb daemon's own xHCI inbound DMA writes are
 * silently lost (a per-process effect we couldn't root-cause), while a
 * separate process drives the same controller fine — proven by the
 * diag-udp 'X' rig in lwip-port. As a PoC, this binary hosts the real
 * USB stack so a working USB keyboard can be enumerated and used.
 *
 * Each shim file in this directory has its own path so Phoenix's build
 * cache stores a distinct .o (the resolved-source-path .o cache would
 * otherwise reuse the usb daemon's .o, which has main()). usb.c is
 * compiled here with -DUSB_NO_MAIN so the embedded copy excludes main();
 * usb_init() remains the entry point the lwip-port main calls.
 */
#include "../../../phoenix-rtos-usb/usb/usb.c"
