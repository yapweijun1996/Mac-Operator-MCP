#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "--exchange") == 0) {
    // An explicit owner upgrade swaps two validated bundles without a missing
    // installation interval. The caller retains the previous bundle for rollback.
    return renamex_np(argv[2], argv[3], RENAME_SWAP) == 0 ? 0 : 74;
  }
  if (argc != 3) return 64;
  // Publish the complete verified bundle without replacing or nesting into an
  // existing installation, whose ad-hoc signature may carry owner TCC grants.
  if (renamex_np(argv[1], argv[2], RENAME_EXCL) == 0) return 0;
  return errno == EEXIST ? 73 : 74;
}
