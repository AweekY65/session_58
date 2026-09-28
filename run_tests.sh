#!/usr/bin/env bash
# 运行全部 OTA 模拟器自动化测试（纯本地，无需网络）
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest discover -s tests -t . -v
