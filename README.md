# 本地安全固件 OTA 更新模拟器

一个**完全本地**的安全固件 OTA（Over-The-Air）更新模拟器：A/B 双分区、
Ed25519 签名验证、SHA-256 镜像校验、版本策略、首次启动健康检查与自动回滚。

- 所有固件镜像、签名、版本元数据、设备状态和更新日志都只存在于**本地文件或内存**；
- **不连接**真实设备、OTA 平台、云存储或任何外部服务（唯一的第三方依赖是本地密码学库 PyNaCl）。

## 目录结构

```
.
├── ota/                      模拟器核心库
│   ├── errors.py             异常类型（签名/哈希/策略/中断/状态错误）
│   ├── _atomic.py            原子文件写入（tmp + fsync + os.replace）
│   ├── keys.py               Ed25519 测试密钥管理
│   ├── manifest.py           manifest、固件包、签名与验证
│   ├── policy.py             版本策略（默认拒降级 + 回滚白名单）
│   ├── device.py             A/B 设备与启动状态机（核心）
│   └── updater.py            更新编排 + 故障注入
├── tools/                    测试镜像生成工具（需要私钥）
│   ├── gen_keys.py           生成 Ed25519 测试密钥对
│   └── build_firmware.py     构建已签名的本地固件包
├── tests/                    自动化测试（unittest，28 个用例）
│   ├── helpers.py
│   └── test_ota.py
├── demo.py                   端到端演示（纯本地，产物在 _demo_workspace/）
├── run_tests.sh              终端一键测试脚本
└── requirements.txt
```

## 快速开始

```bash
pip install -r requirements.txt   # 仅需 PyNaCl（Ed25519）

# 运行全部自动化测试
./run_tests.sh                    # 或 python3 -m unittest discover -t . -s tests -v

# 端到端演示：出厂、升级、降级拒绝、坏固件回滚、白名单回滚
python3 demo.py

# 生成测试密钥
python3 -m tools.gen_keys
# 构建固件包（用测试私钥签名）
python3 -m tools.build_firmware --package ./pkg/v1.0.0 --version 1.0.0 --content "fw-1.0.0"
python3 -m tools.build_firmware --package ./pkg/v2.0.0 --version 2.0.0 --size 262144 --seed 42
```

## 设备存储布局

```
<device_dir>/
├── state.json                 # 设备状态（权威，原子写入）
├── update.log                 # JSON Lines 更新/启动/回滚日志
└── slots/
    ├── a/
    │   ├── slot.json          # {"version", "size", "sha256"}
    │   └── image.bin          # 槽位固件镜像
    └── b/
        ├── slot.json
        └── image.bin
```

## A/B 状态机

`state.json` 中的 `boot_status` 三态：

```
                 update() 验证通过并原子切换
 committed ───────────────────────────────────────► pending
     ▲                                                  │
     │                                       boot() 首检
     │                                                  ▼
     │                                            unconfirmed
     │                                  ┌───────────────┴────────────────┐
     │                          健康检查失败/异常                  健康检查通过
     │ confirm_boot()                   │                                │
     └───────────────────────┐          ▼                                ▼
                             │   下次 boot() 自动回滚          等待 confirm_boot()
                             └──── 旧槽 committed  ◄──────────  确认后 committed
```

- **committed**：`active_slot` 运行的是已确认的好固件，唯一允许下发新更新的状态。
- **pending**：更新已把启动槽原子翻转到新槽，但新固件还没启动过。
- **unconfirmed**：新固件已启动（首检结果记录在 `last_health`），等待显式确认。

启动规则（`Device.boot()`）：

1. **pending**：首次启动新固件，跑健康检查。
   - 通过 → 进入 `unconfirmed`，等待 `confirm_boot()`；
   - 失败或钩子抛异常 → 记录 `last_health=failed`；**下一次 `boot()` 自动回滚**。
2. **unconfirmed**：只要新固件没被确认成功（启动失败、或一直没确认就重启），
   本次启动**立即自动回滚**到 `rollback_slot`（旧槽），并提交为 `committed`。
3. **committed**：正常启动活动槽；活动槽损坏时尝试另一个完整槽位。

### 为什么异常中断后设备总是可启动的（崩溃安全）

- **只写非活动槽**：更新镜像永远写入非活动槽的临时暂存文件，写完并通过
  大小 + SHA-256 复核后才原子替换为 `image.bin`；活动槽在切换前原封不动。
- **状态原子化**：`state.json` / `slot.json` 一律走
  `写临时文件 → fsync → os.replace → fsync(目录)`，磁盘上永远只有
  “完整旧状态”或“完整新状态”，没有半截 JSON。
- **切换是最后一步**：槽位翻转发生在镜像落盘且复核之后；翻转瞬间旧槽
  即成为 `rollback_slot`。因此无论在哪个阶段掉电：
  - 切换前掉电 → 活动槽（旧固件）完整可启动，暂存文件可直接清理后重试；
  - 切换后掉电 → 新槽待首检，旧槽完整保留；新固件失败或不确认 → 自动回滚。

## Manifest 与固件包

固件包是一个本地目录：

```
package_dir/
├── manifest.json
└── image.bin
```

`manifest.json`：

```json
{
  "version": "2.0.0",
  "image": "image.bin",
  "size": 14,
  "sha256": "<64 位十六进制 SHA-256>",
  "signature": "<128 位十六进制 Ed25519 签名>"
}
```

- 签名只覆盖 **canonical manifest**：排除 `signature` 字段本身，
  使用固定的 `UTF-8 + sort_keys + 紧凑分隔符` 序列化，保证字节稳定。
- 验证顺序（`ota.manifest.verify_package`）：
  1. **Ed25519 签名验证**——同时保护版本、大小、哈希等元数据，任何篡改都失效；
  2. **镜像大小**校验；
  3. **镜像 SHA-256** 重新计算比对。
- 任一步失败立即抛出异常，更新器**绝不会写入或激活**该固件。

## 签名与密钥边界

- 算法：**Ed25519**（等价强度的现代非对称签名），由本地 PyNaCl 实现。
- **私钥**（32 字节 seed）只被 `tools/` 下的打包工具用来给测试镜像签名，
  放在 `keys/test_private.key`（演示产物），**不得由更新器持有**。
- **更新器 `Updater(device, public_key, ...)` 只接收公钥**；
  测试 `test_updater_only_takes_public_key` 从构造签名和运行行为两方面保证这一点。
- 这些密钥仅用于本地测试镜像生成，绝不可用于真实设备或生产环境。

## 版本策略与恢复流程

版本策略（`ota.policy.VersionPolicy`）：

- 默认：目标版本必须 ≥ 当前版本，即**默认拒绝降级**；
- 同版本重刷默认允许（可通过 `allow_reinstall=False` 关闭）；
- 可用 `allowed_rollback_versions=("1.0.0",)` **显式配置允许回滚的旧版本白名单**，
  其余降级即使签名合法也会被拒绝（同时防合法旧包重放）。

典型恢复流程（坏固件 / 未确认掉电）：

```
update(v3) ─► boot() 首检失败 ─► boot() 自动回滚 ─► committed @ v2
                     │                  ▲
                     └─ 或：首检通过但未 confirm 就重启 ─┘
```

回滚会向 `update.log` 追加 `boot.rollback` 事件，记录失败槽位、
回滚槽位、回滚版本和原因。

## 故障注入

`ota.updater.FaultInjector` 用于测试“更新任意阶段异常中断”：

```python
from ota import Updater, FaultInjector
from ota.updater import STAGE_WRITE

# 写入非活动槽累计 20000 字节后模拟掉电
Updater(dev, public_key).update(
    pkg_v2, fault=FaultInjector(stage=STAGE_WRITE, after_bytes=20000)
)
# 抛 UpdateInterrupted；设备仍 committed，旧固件可启动，可重试
```

可注入阶段：`verify` / `policy` / `write` / `postcheck` / `switch`。

## 测试命令

```bash
# 全部测试（必须在项目根目录执行）
./run_tests.sh
# 等价于
python3 -m unittest discover -t . -s tests -v
```

覆盖场景（28 个用例）：

| 场景 | 测试类 / 用例 |
| --- | --- |
| 出厂烧录、正常升级、A/B 交替写入、确认前拒绝确认 | `ProvisioningTests` / `NormalUpdateTests` |
| 正常升级全流程（验证→写 B→切换→首检→确认→重启） | `test_full_upgrade_flow` |
| 错误密钥签名、未知公钥、manifest 篡改、签名编码非法 | `SignatureTests` |
| 镜像篡改（SHA-256）、截断镜像（大小）、槽位落盘后损坏 | `ImageTamperTests` |
| 默认拒绝降级、白名单外拒绝、白名单内允许回滚、版本比较 | `VersionPolicyTests` |
| 写入前/写入中/各阶段中断后旧固件仍可启动并可重试 | `InterruptionTests` |
| 切换后掉电、未确认重启自动回滚 | `test_interruption_after_switch_rolls_back_on_next_boot` |
| 首检失败、健康检查异常、未确认自动回滚 | `FirstBootFailureTests` |
| 未确认状态下拒绝再次更新（保护回滚槽） | `test_update_rejected_while_previous_update_unconfirmed` |
| 更新器不依赖私钥、合法旧包重放被策略拦截 | `SecurityBoundaryTests` |
| 更新/回滚日志完整、双槽均损坏时明确报错 | `LoggingTests` / `NoBootableSlotTests` |

## 设计说明与限制

- “固件”是任意字节串；“可启动”在模拟器中定义为
  **槽位元数据存在且镜像大小与 SHA-256 全部一致**；
  固件自身的启动/业务行为通过注入的 `health_check(slot, version, image_path) -> bool`
  钩子模拟（返回 False 或抛异常即启动失败）。
- 模拟器面向**状态机与更新安全**，不模拟 flash 硬件时序；
  原子性由 POSIX `os.replace` 与 `fsync` 提供的真实文件系统保证。
