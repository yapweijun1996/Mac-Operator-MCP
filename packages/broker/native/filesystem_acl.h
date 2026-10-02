#ifndef MOP_FILESYSTEM_ACL_H
#define MOP_FILESYSTEM_ACL_H

#include <sys/acl.h>
#include <sys/stat.h>

#include <cerrno>
#include <unistd.h>

namespace mop {

inline bool HasExtendedAclEntries(const char* path, bool* has_entries) {
  struct stat path_status{};
  if (path == nullptr || has_entries == nullptr || lstat(path, &path_status) != 0 ||
      (!S_ISDIR(path_status.st_mode) && !S_ISREG(path_status.st_mode) && !S_ISSOCK(path_status.st_mode))) return false;

  acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
  if (acl == nullptr) {
    // Darwin may report unsupported ACLs for a Unix socket. Other errors and
    // filesystem object types retain their existing fail-closed behavior.
    if (errno == ENOENT || (S_ISSOCK(path_status.st_mode) && errno == ENOTSUP)) {
      *has_entries = false;
      return true;
    }
    return false;
  }

  acl_entry_t entry;
  errno = 0;
  const int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  const int error = errno;
  acl_free(acl);
  if (result == 0) {
    *has_entries = true;
    return true;
  }
  if (result == -1 && error == EINVAL) {
    *has_entries = false;
    return true;
  }
  return false;
}

}  // namespace mop

#endif  // MOP_FILESYSTEM_ACL_H
