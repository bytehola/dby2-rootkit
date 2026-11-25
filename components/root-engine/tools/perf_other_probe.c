#define _GNU_SOURCE

#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s PID [DURATION_MS]\n", argv[0]);
    return 2;
  }
  pid_t target_pid = (pid_t)strtol(argv[1], NULL, 10);
  int duration_ms =
      argc == 3 ? (int)strtol(argv[2], NULL, 10) : 200;
  int event_pid = target_pid;
  int event_cpu = -1;
  if (target_pid < 0) {
    event_pid = -1;
    event_cpu = -target_pid;
  }

  struct perf_event_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.type = PERF_TYPE_HARDWARE;
  attributes.size = sizeof(attributes);
  attributes.config = PERF_COUNT_HW_CPU_CYCLES;
  attributes.sample_period = 100000;
  attributes.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
                           PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_INTR;
  attributes.sample_regs_intr = (1ULL << 33) - 1;
  attributes.sample_max_stack = 16;
  attributes.exclude_user = 0;
  attributes.exclude_hv = 0;
  attributes.disabled = 1;

  int event_fd =
      (int)syscall(SYS_perf_event_open, &attributes, event_pid, event_cpu, -1,
                   0);
  if (event_fd < 0) {
    printf("perf_event_open pid=%d failed errno=%d\n", target_pid, errno);
    return 1;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  size_t mapping_size = (size_t)page_size * 129;
  void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       event_fd, 0);
  if (mapping == MAP_FAILED) {
    printf("mmap failed errno=%d\n", errno);
    return 1;
  }

  int reset_result = ioctl(event_fd, PERF_EVENT_IOC_RESET, 0);
  int enable_result = ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0);
  usleep((useconds_t)duration_ms * 1000);
  int disable_result = ioctl(event_fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();

  struct perf_event_mmap_page *metadata =
      (struct perf_event_mmap_page *)mapping;
  const char *ring_data = (const char *)mapping + page_size;
  uint64_t ring_size = mapping_size - (size_t)page_size;
  uint64_t head = metadata->data_head;
  uint64_t tail = metadata->data_tail;
  int sample_records = 0;
  while (tail + sizeof(struct perf_event_header) <= head) {
    uint64_t offset = tail & (ring_size - 1);
    struct perf_event_header header;
    memcpy(&header, ring_data + offset, sizeof(header));
    if (header.size < sizeof(header) || tail + header.size > head) {
      break;
    }
    if (header.type == PERF_RECORD_SAMPLE) {
      sample_records++;
    }
    tail += header.size;
  }
  uint64_t count = 0;
  ssize_t count_size = read(event_fd, &count, sizeof(count));
  printf("perf_event_open pid=%d fd=%d reset=%d enable=%d disable=%d "
         "read=%zd count=%llu samples=%d\n",
         target_pid, event_fd, reset_result, enable_result, disable_result,
         count_size, (unsigned long long)count, sample_records);
  munmap(mapping, mapping_size);
  close(event_fd);
  return 0;
}
