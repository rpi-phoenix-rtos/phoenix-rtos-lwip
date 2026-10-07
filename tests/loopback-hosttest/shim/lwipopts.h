/* Host build of the Raspberry Pi 4 lwIP options
 * (phoenix-rtos-project/_projects/aarch64a72-generic-rpi4b/lwip/lwipopts.h)
 * minus the Phoenix-only pieces: the hook file (routing table, packet filter,
 * AF_PACKET) and the /dev link-monitor and ifstatus devices. Every option that
 * shapes the core's threading and locking is kept as on the Pi. */
#include <errno.h>
#include <stdlib.h>

#define LWIP_TCPIP_CORE_LOCKING       1
#define LWIP_TCPIP_CORE_LOCKING_INPUT 1
#define LWIP_SUPPORT_CUSTOM_PBUF      1
#define LWIP_NETIF_LOOPBACK           1
#define LWIP_HAVE_SLIPIF              0
#define LWIP_NETIF_API                1
#define LWIP_SOCKET                   1
#define LWIP_COMPAT_SOCKETS           0
#define LWIP_ARP                      1
#define LWIP_ICMP                     1
#define LWIP_RAW                      1
#define LWIP_DHCP                     1
#define LWIP_DNS                      0 /* the Pi: 1 (netdb needs Phoenix types) */
#define LWIP_RAND()                   ((u32_t)rand())
#define LWIP_AUTOIP                   1
#define LWIP_UDP                      1
#define LWIP_TCP                      1
#define LWIP_TCP_KEEPALIVE            1
#define MEM_LIBC_MALLOC               1
#define MEMP_MEM_MALLOC               1
#define LWIP_ERRNO_INCLUDE            "errno.h"
#define LWIP_DNS_API_DEFINE_ERRORS    0
#define LWIP_DNS_API_DEFINE_FLAGS     0
#define LWIP_DNS_API_DECLARE_STRUCTS  0
#define LWIP_DNS_API_DECLARE_H_ERRNO  0
#define MEMP_NUM_NETCONN              1024
#define PPP_SUPPORT                   0
#define LWIP_TIMEVAL_PRIVATE          0

#define TCP_MSS                       1460
#define TCP_WND                       (44 * TCP_MSS)
#define TCP_SND_BUF                   TCP_WND
#define LWIP_INGRESS_CREDIT           1
#define TCP_SND_QUEUELEN              192
#define ETH_PAD_SIZE                  2
#define ETHARP_TABLE_MATCH_NETIF      1
#define IP_REASSEMBLY                 1
#define IP_FRAG                       1
#define SO_REUSE                      1
#define DEFAULT_THREAD_STACKSIZE      (4 * 4096)
#define TCPIP_THREAD_STACKSIZE        (4 * 4096)
#define TCPIP_THREAD_PRIO             3
#define TCPIP_MBOX_SIZE               256
#define DEFAULT_RAW_RECVMBOX_SIZE     32
#define DEFAULT_UDP_RECVMBOX_SIZE     32
#define DEFAULT_TCP_RECVMBOX_SIZE     32
#define DEFAULT_ACCEPTMBOX_SIZE       32
#define LWIP_NETIF_STATUS_CALLBACK    1
#define LWIP_DHCP_AUTOIP_COOP         1
#define LWIP_DHCP_AUTOIP_COOP_TRIES   3
#define LWIP_SO_RCVTIMEO              1
#define LWIP_SO_SNDTIMEO              1
#define LWIP_NETIF_LINK_CALLBACK      1
#define PBUF_LINK_HLEN                44
#define LWIP_NETIF_REMOVE_CALLBACK    1

#define LWIP_STATS                    1
#define LWIP_STATS_DISPLAY            1
