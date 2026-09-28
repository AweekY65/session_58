#!/usr/bin/env bash
# 在终端运行全部自动化测试。
#
# 用法:
#   ./run_tests.sh            # 运行全部测试
#   ./run_tests.sh -v         # 详细输出
#   ./run_tests.sh -k Policy  # 按关键字过滤（unittest 的 -k，Python 3.10+）
set -euo pipefail

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

# -t . 把项目根作为顶层导入目录，使 tests 包的相对导入生效。
exec "$PYTHON" -m unittest discover -t . -s tests "$@"
