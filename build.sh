#!/bin/sh
set -eu

plugin_os="$(go env GOOS)"
plugin_arch="$(go env GOARCH)"

case "$plugin_os" in
  darwin) plugin_ext="dylib" ;;
  windows) plugin_ext="dll" ;;
  *) plugin_ext="so" ;;
esac

plugin_dir="${CPA_PLUGIN_DIR:-plugins}"
output_dir="$plugin_dir/$plugin_os/$plugin_arch"
output="$output_dir/kiro-go.$plugin_ext"

mkdir -p "$output_dir"
CGO_ENABLED=1 go build -buildmode=c-shared -o "$output" .
rm -f "$output_dir/kiro-go.h"
printf 'Built %s\n' "$output"
