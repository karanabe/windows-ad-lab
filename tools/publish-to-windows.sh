#!/usr/bin/env bash
set -euo pipefail

readonly SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
declare -a RSYNC_OPTIONS=(-av)
DRY_RUN=false

usage() {
  echo "Usage: $0 [--dry-run] [--delete]" >&2
  echo "Set LAB_WINDOWS_COPY to a WSL path for the Windows execution copy." >&2
  echo "Default: /mnt/d/Lab/windows-ad-lab" >&2
}

while (($# > 0)); do
  case "$1" in
    --dry-run)
      RSYNC_OPTIONS+=(--dry-run)
      DRY_RUN=true
      ;;
    --delete)
      RSYNC_OPTIONS+=(--delete)
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  shift
done

if [[ -n "${LAB_WINDOWS_COPY:-}" ]]; then
  DEST_DIR="$LAB_WINDOWS_COPY"
else
  if [[ ! -d /mnt/d ]]; then
    echo "D: drive is not mounted at /mnt/d. Set LAB_WINDOWS_COPY to a WSL path for the Windows execution copy." >&2
    exit 1
  fi
  DEST_DIR="/mnt/d/Lab/windows-ad-lab"
fi

if [[ -e "$DEST_DIR" && ! -d "$DEST_DIR" ]]; then
  echo "LAB_WINDOWS_COPY is not a directory: $DEST_DIR" >&2
  exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "rsync is required. Install it in WSL before publishing." >&2
  exit 1
fi

if [[ "$DRY_RUN" == false ]] && ! command -v git >/dev/null 2>&1; then
  echo "git is required to write build provenance metadata." >&2
  exit 1
fi

mkdir -p "$DEST_DIR"

rsync "${RSYNC_OPTIONS[@]}" \
  --exclude '.git/' \
  --exclude '.gitignore' \
  --exclude 'logs/' \
  --exclude '*.log' \
  --exclude 'config/LabSecrets.psd1' \
  --exclude 'artifacts/' \
  --exclude 'scenarios/rusthound-dev/' \
  "$SOURCE_DIR/" \
  "$DEST_DIR/"

if [[ "$DRY_RUN" == false ]]; then
  git -C "$SOURCE_DIR" rev-parse HEAD > "$DEST_DIR/BUILD_COMMIT"
  git -C "$SOURCE_DIR" status --short > "$DEST_DIR/BUILD_STATUS"
  date --utc '+%Y-%m-%dT%H:%M:%SZ' > "$DEST_DIR/BUILD_PUBLISHED_AT"
  echo "Published to $DEST_DIR"
else
  echo "Dry run completed for $DEST_DIR"
fi
