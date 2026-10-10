#!/bin/sh
set -eu

rust_target="$(rustc -vV | awk '/^host: / {print $2}')"
rust_arch="${rust_target%%-*}"
case "$rust_target" in
  *-apple-darwin) plugin_os="darwin" ;;
  *-pc-windows-*) plugin_os="windows" ;;
  *-linux-*) plugin_os="linux" ;;
  *) printf 'Unsupported Rust host target: %s\n' "$rust_target" >&2; exit 1 ;;
esac

case "$rust_arch" in
  x86_64) plugin_arch="amd64" ;;
  aarch64) plugin_arch="arm64" ;;
  i686|i586) plugin_arch="386" ;;
  armv7|arm) plugin_arch="arm" ;;
  *) printf 'Unsupported Rust target architecture: %s\n' "$rust_arch" >&2; exit 1 ;;
esac

case "$plugin_os" in
  darwin) plugin_ext="dylib" ;;
  windows) plugin_ext="dll" ;;
  *) plugin_ext="so" ;;
esac

plugin_dir="${CPA_PLUGIN_DIR:-plugins}"
output_dir="$plugin_dir/$plugin_os/$plugin_arch"
output="$output_dir/kiro-go.$plugin_ext"

mkdir -p "$output_dir"
cargo build --release

case "$plugin_os" in
  darwin) library="target/release/libkiro_go.dylib" ;;
  windows) library="target/release/kiro_go.dll" ;;
  *) library="target/release/libkiro_go.so" ;;
esac

if [ ! -f "$library" ]; then
  printf 'Rust plugin artifact not found: %s\n' "$library" >&2
  exit 1
fi

cp "$library" "$output"
printf 'Built %s\n' "$output"
