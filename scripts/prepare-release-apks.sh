#!/usr/bin/env bash
set -euo pipefail

tag_name="${TAG_NAME:-local}"
app_asset_name="${APP_ASSET_NAME:-range-scout}"
apk_root="${APK_ROOT:-app/build/outputs/apk}"
asset_dir="${ASSET_DIR:-app/build/release-assets}"

release_dir="$apk_root/release"

copy_required_match() {
  local source_dir="$1"
  local pattern="$2"
  local output_name="$3"
  local matches=()

  while IFS= read -r match; do
    matches+=("$match")
  done < <(find "$source_dir" -maxdepth 1 -type f -name "$pattern" | sort)

  if [ "${#matches[@]}" -ne 1 ]; then
    echo "Expected exactly one APK matching $source_dir/$pattern, found ${#matches[@]}." >&2
    printf '%s\n' "${matches[@]}" >&2
    exit 1
  fi

  cp "${matches[0]}" "$asset_dir/$output_name"
}

if [ ! -d "$release_dir" ]; then
  echo "APK output directory is missing. Run Gradle assembleRelease first." >&2
  exit 1
fi

if find "$release_dir" -maxdepth 1 -type f -name "*release-unsigned.apk" | grep -q .; then
  echo "Unsigned release APK detected. Configure release signing before publishing." >&2
  find "$release_dir" -maxdepth 1 -type f -name "*release-unsigned.apk" -print >&2
  exit 1
fi

rm -rf "$asset_dir"
mkdir -p "$asset_dir"

release_abis=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

for abi in "${release_abis[@]}"; do
  copy_required_match "$release_dir" "*-$abi-release.apk" "$app_asset_name-$tag_name-$abi-release-signed.apk"
done

copy_required_match "$release_dir" "*universal-release.apk" "$app_asset_name-$tag_name-universal-release-signed.apk"

find "$asset_dir" -maxdepth 1 -type f -name "*.apk" -print | sort
