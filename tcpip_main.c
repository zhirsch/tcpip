#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFLEN 100
#define DEV "/dev/net/tap"

#define ARP_ETHERNET 0x0001
#define ARP_IPV4     0x0800

#define ARP_REQUEST 0x0001
#define ARP_REPLY   0x0002

struct netdev {
  int fd;
  uint32_t ip;
  uint8_t mac[6];
};

struct eth_hdr {
  unsigned char dmac[6];
  unsigned char smac[6];
  uint16_t ethertype;
  unsigned char payload[];
} __attribute__((packed));

struct arp_hdr {
  uint16_t hwtype;
  uint16_t protype;
  unsigned char hwsize;
  unsigned char prosize;
  uint16_t opcode;
  unsigned char data[];
} __attribute__((packed));

struct arp_ipv4 {
  unsigned char smac[6];
  uint32_t sip;
  unsigned char dmac[6];
  uint32_t dip;
} __attribute__((packed));

static void info(const char* format, ...) {
  va_list argp;
  va_start(argp, format);
  vfprintf(stderr, format, argp);
  va_end(argp);
}

static int run(const char* format, ...) {
  va_list argp;
  char cmd[BUFLEN + 1];

  va_start(argp, format);
  if (vsnprintf(cmd, BUFLEN, format, argp) < 0) {
    info("failed to format command %s\n", format);
    return -1;
  }
  va_end(argp);
  info("%s\n", cmd);
  return system(cmd);
}

static int running = 1;
static void stop() { running = 0; }

static int init_signals() {
  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = stop;
  if (sigaction(SIGINT, &sa, NULL) < 0) {
    perror("sigaction");
    return -1;
  }
  return 0;
}

static int tap_alloc(char* dev) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open(DEV, O_RDWR)) < 0) {
    perror("tap_alloc");
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
    perror("tap_alloc");
    close(fd);
    return -1;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

int netdev_init(struct netdev* netdev, int fd) {
  memset(netdev, 0, sizeof(*netdev));

  netdev->fd = fd;

  switch (inet_pton(AF_INET, "10.1.10.42", &netdev->ip)) {
  case -1:
    perror("inet_pton");
    return -1;
  case 0:
    info("bad ipv4 address: 10.1.10.42\n");
    return -1;
  }

  // TODO: use the same mac as the interface.
  netdev->mac[0] = 0x00;
  netdev->mac[1] = 0x0c;
  netdev->mac[2] = 0x29;
  netdev->mac[3] = 0x6d;
  netdev->mac[4] = 0x50;
  netdev->mac[5] = 0x25;

  return 0;
}

int tap_read(int fd, char* buf, int buflen) {
  fd_set read_fds;
  struct timeval timeout;
  int nread;

  FD_ZERO(&read_fds);
  FD_SET(fd, &read_fds);

  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  if (select(fd + 1, &read_fds, NULL, NULL, &timeout) <= 0) {
    return 0;
  }

  if ((nread = read(fd, buf, buflen)) < 0) {
    perror("read");
    return -1;
  }
  return nread;
}

static const char* format_ip(uint32_t ip) {
  struct in_addr ip_addr;
  ip_addr.s_addr = ip;
  return inet_ntoa(ip_addr);
}

static const char* format_mac(const unsigned char mac[6]) {
  static char str[18];
  snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
	   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return str;
}

static void tap_write(int fd, void* buf, int len) {
  write(fd, buf, len);
}

static void netdev_send(struct netdev* netdev, struct eth_hdr* hdr,
			uint16_t ethertype, int len,
			const unsigned char dmac[6]) {
  hdr->ethertype = htons(ethertype);
  memcpy(hdr->smac, netdev->mac, 6);
  memcpy(hdr->dmac, dmac, 6);
  len += sizeof(struct eth_hdr);
  tap_write(netdev->fd, (void*)hdr, len);
}

static void arp_out(struct netdev* netdev, struct eth_hdr* hdr,
		    struct arp_hdr* arphdr) {
  struct arp_ipv4* arp4;
  int len;

  arp4 = (struct arp_ipv4*)arphdr->data;

  memcpy(arp4->dmac, arp4->smac, 6);
  arp4->dip = arp4->sip;
  memcpy(arp4->smac, netdev->mac, 6);
  arp4->sip = netdev->ip;

  arphdr->opcode = htons(ARP_REPLY);

  len = sizeof(struct arp_hdr) + sizeof(struct arp_ipv4);
  netdev_send(netdev, hdr, ETH_P_ARP, len, arp4->dmac);
}

static void arp_in(struct netdev* netdev, struct eth_hdr* hdr) {
  struct arp_hdr* arphdr;
  struct arp_ipv4* arp4;

  arphdr = (struct arp_hdr*)hdr->payload;

  if (ntohs(arphdr->hwtype) != ARP_ETHERNET) {
    info("arp: unsupported hwtype: %x\n", ntohs(arphdr->hwtype));
    return;
  }

  if (ntohs(arphdr->protype) != ARP_IPV4) {
    info("arp: unsupported protype: %x\n", ntohs(arphdr->protype));
    return;
  }

  arp4 = (struct arp_ipv4*)arphdr->data;

  info("arp: smac=%s\n", format_mac(arp4->smac));
  info("arp:  sip=%s\n", format_ip(arp4->sip));
  info("arp: dmac=%s\n", format_mac(arp4->dmac));
  info("arp:  dip=%s\n", format_ip(arp4->dip));

  if (netdev->ip != arp4->dip) {
    info("arp: ip %x != dip %x\n", netdev->ip, arp4->dip);
    return;
  }

  switch (ntohs(arphdr->opcode)) {
  case ARP_REQUEST:
    arp_out(netdev, hdr, arphdr);
    break;
  default:
    info("arp: unknown opcode %x\n", ntohs(arphdr->opcode));
    break;
  }
}

static void handle_frame(struct netdev* netdev, struct eth_hdr* hdr) {
  /* info("eth: smac=%s\n", format_mac(hdr->smac)); */
  /* info("eth: dmac=%s\n", format_mac(hdr->dmac)); */

  switch (ntohs(hdr->ethertype)) {
  case ETH_P_ARP:
    info("ETH_P_ARP\n");
    arp_in(netdev, hdr);
    break;
  case ETH_P_IPV6:
    info("ETH_P_IPV6\n");
    break;
  case ETH_P_IP:
    info("ETH_P_IP\n");
    break;
  default:
    info("unknown ethertype %x\n", hdr->ethertype);
    break;
  }
}

int main() {
  char dev[IFNAMSIZ + 1] = {'\0'};
  int fd;
  struct netdev netdev;

  // Exit on SIGINT.
  if (init_signals() < 0) {
    return 1;
  }

  // Get the tap device to use.
  if ((fd = tap_alloc(dev)) < 0) {
    return 1;
  }
  if (run("ip link set dev %s up", dev) < 0) {
    close(fd);
    return 1;
  }
  if (run("ip route add dev %s 10.0.0.0/24", dev) < 0) {
    close(fd);
    return 1;
  }
  if (run("ip address add dev %s local 10.1.10.41", dev) < 0) {
    close(fd);
    return 1;
  }
  info("tap_alloc: %s\n", dev);

  if (netdev_init(&netdev, fd) < 0) {
    close(fd);
    return 1;
  }
  
  // Read from the device.
  while (running) {
    char buf[BUFLEN];
    if (tap_read(fd, buf, BUFLEN) <= 0) {
      continue;
    }
    struct eth_hdr* hdr;
    hdr = (struct eth_hdr*)buf;
    handle_frame(&netdev, hdr);
  }

  close(fd);
  info("goodbye\n");
  return 0;
}
