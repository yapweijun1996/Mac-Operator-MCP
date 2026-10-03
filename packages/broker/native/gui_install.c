#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 3) return 64;
  // Publish the complete verified bundle without replacing or nesting into an
  // existing installation, whose ad-hoc signature may carry owner TCC grants.
  if (renamex_np(argv[1], argv[2], RENAME_EXCL) == 0) return 0;
  return errno == EEXIST ? 73 : 74;
}
