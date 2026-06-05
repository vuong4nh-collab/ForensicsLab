#!/bin/bash
# Docker entrypoint for ForensicsLab sandbox
# Sets up the environment and starts bash

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       ForensicsLab — Kali Linux Sandbox v1.0            ║"
echo "║   Môi trường phân tích chứng cứ số an toàn, cô lập      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Thư mục làm việc: /evidence/scenario_<lab>"
echo "[*] Gõ 'ls' để xem danh sách file chứng cứ"
echo "[*] Các công cụ: tshark, fls, icat, ewfinfo, vol/volatility3, xxd, strings"
echo ""

# Set a nice prompt
export PS1='\[\033[01;32m\]root@kali-sandbox\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]# '

exec "$@"
