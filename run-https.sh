#!/bin/sh
set -eu
cd "$(dirname "$0")"
: "${LAN_HOST:?LAN_HOST değişkenine bu bilgisayarın yerel ağ IP adresini yazın}"
mkdir -p .data/caddy .data/caddy-config
export XDG_DATA_HOME="$(pwd)/.data/caddy"
export XDG_CONFIG_HOME="$(pwd)/.data/caddy-config"
exec caddy run --config Caddyfile
