/*
 * Wake ueventd with synthetic kernel object events so the remote task
 * sampler has scheduler activity to observe.
 */
#include <errno.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int duration_seconds = argc > 1 ? atoi(argv[1]) : 30;
  int socket_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
  if (socket_fd < 0) {
    fprintf(stderr, "uevent socket failed errno=%d (%s)\n",
            errno, strerror(errno));
    return 1;
  }

  struct sockaddr_nl destination;
  memset(&destination, 0, sizeof(destination));
  destination.nl_family = AF_NETLINK;
  destination.nl_pid = 1;
  destination.nl_groups = 1;

  static const char event[] =
      "add@/devices/virtual/input/input0";
  for (int iteration = 0; iteration < duration_seconds * 1000; iteration++) {
    ssize_t sent = sendto(socket_fd, event, sizeof(event), 0,
                          (struct sockaddr *)&destination,
                          sizeof(destination));
    if (sent < 0 && errno != EAGAIN) {
      fprintf(stderr, "uevent send failed errno=%d (%s)\n",
              errno, strerror(errno));
      close(socket_fd);
      return 1;
    }
    usleep(1000);
  }

  close(socket_fd);
  return 0;
}
