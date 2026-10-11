# Shared protected-state snapshot operations. Publish and restore only completed copies.
backup_protected_state() {
  local state_root="$1" backup_root="$2"
  [[ ! -e "$backup_root/state" && ! -e "$backup_root/state.partial" ]] || return 1
  cp -Rp "$state_root" "$backup_root/state.partial" || return 1
  mv "$backup_root/state.partial" "$backup_root/state" || return 1
}

restore_protected_state() {
  local state_root="$1" backup_root="$2" stamp="$3"
  local restore_root="$state_root.restore-$stamp" failed_root="$state_root.failed-$stamp"
  [[ -d "$backup_root/state" && ! -e "$restore_root" && ! -e "$failed_root" ]] || return 1
  cp -Rp "$backup_root/state" "$restore_root" || return 1
  mv "$state_root" "$failed_root" || return 1
  if ! mv "$restore_root" "$state_root"; then
    mv "$failed_root" "$state_root" || echo "original state remains at $failed_root" >&2
    return 1
  fi
}
