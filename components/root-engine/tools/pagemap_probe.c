#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  void *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  *(volatile unsigned char *)page = 0x5a;

  int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("open pagemap");
    return 2;
  }

  uint64_t entry = 0;
  uint64_t page_index = (uint64_t)(uintptr_t)page / page_size;
  off_t offset = (off_t)(page_index * sizeof(entry));
  if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
    perror("pread pagemap");
    close(fd);
    return 3;
  }
  close(fd);

  uint64_t pfn = entry & ((1ULL << 55) - 1);
  uint64_t physical = pfn * page_size + ((uintptr_t)page & (page_size - 1));
  printf("page=%p entry=%#llx pfn=%#llx physical=%#llx present=%llu "
         "direct_ffffff80=%#llx\n",
         page, (unsigned long long)entry, (unsigned long long)pfn,
         (unsigned long long)physical, (unsigned long long)(entry >> 63),
         (unsigned long long)(0xffffff8000000000ULL + physical));
  return 0;
}
