# 本地安全固件 OTA 更新模拟器

一个**完全离线**的 A/B 分区固件 OTA 更新模拟器：Ed25519 数字签名验证、
SHA-256 镜像完整性校验、防降级版本策略、首次启动健康检查与失败自动回滚、
任意阶段断电后状态仍指向完整可启动槽位。

- 所有固件镜像、签名、manifest、设备状态与日志**只使用本地文件/内存**；
- 不连接任何真实设备、OTA 平台、云存储或外部服务；
- 纯 Python 3 标准库 + [`cryptography`](https://cryptography.io/)（Ed25519）；
- 自动化测试用标准库 `unittest`，终端一条命令即可运行。

## 目录结构

```
.
├── ota/                    # 设备侧更新器（只持有公钥，永不读取私钥）
│   ├── errors.py           #   各阶段异常类型
│   ├── keys.py             #   Ed25519 测试密钥生成/加载（PEM）
│   ├── manifest.py         #   manifest 规范化、签名/验签
│   ├── image.py            #   测试固件镜像格式与 SHA-256 校验
│   ├── storage.py          #   槽位文件、原子 state.json、JSONL 日志
│   ├── device.py           #   A/B 状态机：update / boot / confirm / rollback
│   └── cli.py              #   设备侧命令行（init/status/update/boot/confirm/log）
├── tools/
│   └── sign_image.py       # 镜像签名工具 —— 工程中唯一读取私钥的组件
├── tests/                  # 39 个自动化测试
└── run_tests.sh            # 一键运行全部测试
```

**私钥隔离**：`tools/sign_image.py` 模拟厂商离线签名工厂，是唯一接触私钥的组件；
设备侧（`ota/`）只接受出厂烧录的公钥（`devdir/pubkey.pem`，模拟 ROM 根信任），
更新流程任何环节都不要求持有私钥。

## 快速开始

```bash
pip install -r requirements.txt          # cryptography（本机已有可跳过）

# 1. 生成本地测试密钥对
python3 -m ota.keys --dir /tmp/ota/keys

# 2. 签名出厂固件 1.0.0
python3 tools/sign_image.py --priv-key /tmp/ota/keys/test_private.pem \
    --image-out /tmp/ota/fw100.bin --manifest-out /tmp/ota/fw100.json \
    --version 1.0.0 --size 128

# 3. 初始化设备（烧录公钥 + 出厂固件到 A 槽）
python3 -m ota.cli init --dir /tmp/ota/dev \
    --pub-key /tmp/ota/keys/test_public.pem \
    --factory-manifest /tmp/ota/fw100.json --factory-image /tmp/ota/fw100.bin

# 4. 签名并下发 1.1.0 更新（写入非活动槽 B）
python3 tools/sign_image.py --priv-key /tmp/ota/keys/test_private.pem \
    --image-out /tmp/ota/fw110.bin --manifest-out /tmp/ota/fw110.json \
    --version 1.1.0 --size 512
python3 -m ota.cli update --dir /tmp/ota/dev \
    --manifest /tmp/ota/fw110.json --image /tmp/ota/fw110.bin

# 5. 重启：首次启动健康检查通过 → testing；确认良好 → 原子提交
python3 -m ota.cli boot    --dir /tmp/ota/dev
python3 -m ota.cli confirm --dir /tmp/ota/dev

python3 -m ota.cli status  --dir /tmp/ota/dev
python3 -m ota.cli log     --dir /tmp/ota/dev
```

签名工具常用参数：`--version`、`--size 载荷字节数`、`--health good|bad`
（`bad` = 合法签名但启动健康检查失败，用于演示自动回滚）。

## A/B 状态机

每台设备有两个等权槽位 `a` / `b`。`state.json` 中三个关键指针：

| 字段 | 含义 |
|---|---|
| `active_slot` | **已确认良好**、被承诺可启动的槽位（任何时刻都完整） |
| `boot_slot` | 下一次启动将使用的槽位 |
| `boot_state` | `normal` / `pending` / `testing` |

```
                provision()
                    │
                    ▼
        ┌──────────────────────┐
        │ boot_state=normal    │◄──────────────────────────┐
        │ active=boot=A        │                           │
        └──────────┬───────────┘                           │
                   │ update() 只写非活动槽位 B，原子改指针    │
                   ▼                                       │
        ┌──────────────────────┐  boot() 健康检查失败        │
        │ boot_state=pending   │──────► rollback ───────────┤
        │ boot=B, active=A     │                           │
        └──────────┬───────────┘                           │
                   │ boot() 健康检查通过                     │
                   ▼                                       │
        ┌──────────────────────┐  未 confirm 再次 boot()    │
        │ boot_state=testing   │──────► rollback ───────────┤
        │ boot=B, active=A     │                           │
        └──────────┬───────────┘                           │
                   │ confirm() 原子提交                     │
                   ▼                                       │
        ┌──────────────────────┐                           │
        │ boot_state=normal    │                           │
        │ active=boot=B        │                           │
        └──────────────────────┘  （A 完整保留为下次更新目标）
```

- **update**：选 `active_slot` 的对侧槽位写入；`active_slot` 的字节全程不被触碰。
- **boot（pending）**：对候选槽位做首次启动健康检查 —— 失败立即回滚旧版本；
  通过则进入 `testing`，等待显式 `confirm`。
- **boot（testing）**：新固件未确认就再次启动（看门狗/人工重启）→ 自动回滚。
- **confirm**：仅 `testing` 可确认；一次原子写把 `active_slot` 切到新槽位。
  旧槽位保留为 `valid`，作为下一次更新的写入目标与回滚保险。

## Manifest 与签名验证

Manifest 是 JSON 文档：

```json
{
  "version": "1.1.0",
  "image": "firmware-1.1.0.bin",
  "size": 660,
  "sha256": "8ce5d0c0…07635",
  "created_at": "2026-09-28T10:00:00Z",
  "signature": "<base64 Ed25519 签名>"
}
```

- **签名对象**：去掉 `signature` 字段后的规范化 JSON
  （`json.dumps(..., sort_keys=True, separators=(",", ":"))`）；
- **算法**：Ed25519（64 字节签名），公钥在 `init` 时烧录到设备目录；
- 验证顺序固定为 **先验签 → 再校验镜像大小/SHA-256 → 再查版本策略 → 最后写盘**，
  因此签名错误、manifest 任一字段被篡改、镜像被翻转一个字节，都会在触碰槽位前被拒绝；
- 写入暂存文件后还会复核一次哈希，再 `os.replace` 原子落盘，防落盘过程损坏。

## 版本策略（防降级）

- 按数字版本号比较（`1.9.0 < 1.10.0`，不是字符串比较）；
- 目标版本 **低于** 当前 active 版本时默认拒绝（`DowngradeRejected`）；
- 同版本重刷、更高版本放行；
- 可显式配置回滚白名单：

```bash
python3 -m ota.cli update --dir /tmp/ota/dev \
    --manifest old.json --image old.bin --allow-rollback 1.0.0
```

白名单持久化在 `state.json.allowed_rollback_versions` 中；仅白名单内的精确版本
允许降级安装。

## 恢复流程（断电一致性）

设备每次重新打开（`Device(devdir)`，即模拟上电）都会执行 `_reconcile`：

1. 删除所有 `slots/*.tmp` 写入暂存（中断的半成品永远不会被当成固件）；
2. 对登记为 `valid` 的槽位重算 SHA-256：文件缺失或哈希不符 → 标记 `failed`；
3. 若 `pending/testing` 候选槽位已不完整 → 启动指针立刻恢复到 `active_slot`；
4. 全部状态变更通过 **临时文件 + fsync + `os.replace`** 原子写入 `state.json`，
   槽位落盘同样用 `os.replace`（并 fsync 目录）。

中断点对照（均有测试覆盖）：

| 中断阶段 | 恢复后行为 |
|---|---|
| 验签/版本策略失败 | 未做任何写入，设备原样运行 |
| 镜像分块写入途中 | `*.tmp` 被清理，`state.json` 从未改变，重试即可 |
| 槽位已 replace、state 未切换 | 状态仍指向旧槽位；新槽位未登记，可重新更新 |
| pending 时槽位损坏 | 重启后标记 failed，回到 active 旧固件 |
| 首次启动健康检查失败 | boot 当场回滚，候选标记 failed，旧固件继续运行 |
| testing 未确认就重启 | 再次 boot 自动回滚旧版本 |

不变量：**任何阶段异常中断后，`active_slot` 始终指向一个完整且可启动的固件槽位。**

## 更新日志

设备目录下 `update.log` 为追加式 JSONL，记录关键事件：
`factory_installed`、`update_started`、`update_pending`、`signature_rejected`、
`image_rejected`、`downgrade_rejected`、`rollback_allowed`、`write_interrupted`、
`boot_ok`、`boot_normal`、`rollback`、`confirmed`、`recovered_*` 等。

## 运行测试

```bash
./run_tests.sh
# 等价于：
python3 -m unittest discover -s tests -t . -v
```

39 个测试覆盖：

- 正常升级（A→B→A 往返、确认前后重启）；
- 签名错误（他人密钥签名、manifest 字段篡改、签名字节篡改、缺签名）；
- 镜像篡改（写字节翻转、截断、垃圾内容、落盘后损坏槽位）；
- 降级拒绝、同版本重刷、白名单显式允许回滚；
- 写入中断（分块写中途断电、重启恢复、重试成功）；
- 槽位落盘后 state 切换前崩溃；
- 首次启动健康检查失败与自动回滚（含跨重启）；
- testing 未确认重启自动回滚、确认后跨重启持久化；
- active 槽位字节在更新全程不变、暂存文件重启清理。

## 说明

本工程仅用于本地教学/测试：密钥是本地生成的测试密钥，镜像格式与健康检查
均为模拟实现，不对应任何真实硬件引导链或 OTA 协议。
