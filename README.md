# qq-reader

**English summary:** `qq-reader` is the read-only connection pipeline
that lets an AI assistant (**Muse**) plug into your *own* QQ account:
a scheduled agent SSHes into the QQ host, runs one pull command, and
gets new messages back as structured JSON lines. The foundation layer
is a reader for the QQNT local message database on Linux (developed
and verified against the official Linux QQ **3.2.34**). QQ stores chat
history in SQLCipher-encrypted SQLite files whose key exists only in
the running client's memory. The toolkit (1) recovers that key by
scanning the QQ process's memory and verifying candidates against
page 1 of a database *copy* with HMAC, (2) decrypts copies of
`nt_msg.db` / `group_msg_fts.db` / `group_info.db`, (3) parses the
protobuf message bodies, and (4) emits only the messages newer than a
server-side watermark as JSON lines. It is read-only by construction:
no network code, no protocol login, it never writes to QQ's files and
never touches `login.db`. The repo also documents the full workflow
(`docs/ARCHITECTURE.md`, `docs/MUSE-INTEGRATION.md`) and a minimal
patrol-loop spec (`examples/patrol-loop.example.md`). What the
assistant does with the messages afterwards is defined by the user,
outside this pipeline. **For your own account's local data only; not
affiliated with Tencent; decrypting QQ's database may violate the QQ
Terms of Service — use at your own risk.** See the disclaimer below.

---

## 这是什么

**Muse 接入 QQ 的连接与只读读取流程**：把一个 AI 助手接到你
自己账号的 QQ 上——助手通过 SSH 定时调用部署在 QQ 主机上的拉
取脚本，把新消息以结构化 JSON 文本取回来。取钥、解密、解析、
增量，全部只读；不注入、不做协议登录、不联网。

筛选与提醒规则由使用者在助手侧自行定义，不属于本流程的一部
分，本仓库不提供也不预设任何规则。

系统分层，本仓库全部提供：

| 层 | 内容 | 在哪 |
|---|---|---|
| 基础层：读取 | 取钥、解密、解析、增量拉取（下文详述） | 本目录的 Python 脚本 |
| 架构层：设计 | 组件、数据流与设计原则 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| 接入层：连接 | 如何接进 Muse 的定时任务、输出契约、状态与故障处理 | [docs/MUSE-INTEGRATION.md](docs/MUSE-INTEGRATION.md) |
| 示例 | 纯机械的最小巡查循环规格（触发 → 一条 SSH 命令 → 读状态行与消息行） | [examples/patrol-loop.example.md](examples/patrol-loop.example.md) |

其中**基础层**是一个**只读**的 QQNT 本地聊天数据库读取工具包，
面向 Linux 官方 QQ **3.2.34**（在此版本上开发并完整验证；其他
版本不保证可用）。

QQ 客户端每收到一条消息都会写进本地数据库，但数据库是 SQLCipher
加密的，普通 SQLite 打不开。本工具包做四件事：

1. **取钥**：从正在运行的 QQ 进程内存里找回数据库钥匙；
2. **解密**：把数据库的**副本**解密成普通 SQLite；
3. **解析**：把消息体里的 protobuf 还原成（群、发送者、时间、正文、@ 目标）；
4. **增量输出**：按水位线只输出新消息的 JSON 行，供助手侧 /
   你自己的脚本消费。

## 让 Muse 帮你部署

本仓库就是按“**由 AI 助手部署**”设计的——参考部署（Muse）
从头到尾的实际过程是：人只做了三件事（见下），部署脚本、取
钥、写配置、副本验证、创建定时拉取任务，全部由助手自己完成。
你不需要照着文档手动敲命令；把下面这段话粘贴给你的 Muse
（或等价的助手环境）即可：

> 请把这个仓库部署到我的 QQ 主机上：克隆仓库、装好依赖并设
> 好工作目录权限；在 QQ 保持登录时运行取钥扫描，生成
> `key.json`；按 `config.example.json` 写好我的配置；用
> `parse_proof.py` 对一份解密副本做验证；最后在你的定时任
> 务里创建一个周期性拉取任务（调用 `patrol_pull.py`），完成
> 后告诉我结果。需要我扫码登录 QQ 时喊我。

**人需要做的**只有：

- 提供一台服务器（云服务器即可）及 root 权限——除此之外不需要再准备任何机器或环境，Muse 运行的那一端由它自带（清单见下文“使用前你需要
  准备什么”）；
- 在那台主机的官方 QQ 客户端里**扫码登录你自己的账号**；
- 助手询问时，**批准它读取 QQ 进程内存取钥**（这是取钥的必
  经一步，理由见“工作原理”；批准后，日常换钥重扫为自动进
  行）。

**Muse 自动完成的**包括：

- 把脚本部署到 QQ 主机、安装依赖、设好工作目录权限；
- 在 QQ 登录状态下运行取钥扫描、生成 `key.json`；
- 按你的 QQ 号写好 `config.json` 与身份缓存；
- 对解密副本做 sanity check 验证，并完成水位线初始化；
- 创建定时拉取任务并接入助手；
- 日常运行中的异常自愈（QQ 重新登录导致钥匙更换时自动重扫
  取钥）——只有扫码登录这类必须本人操作的环节，助手才会喊
  你。

下文的“部署步骤”是这套部署的完整清单：交给助手时是它的执
行清单，手动部署时也可照单逐项操作。

## 工作原理

### 为什么钥匙只能去内存里找

解密钥匙（dbPassphrase）**不是 QQ 密码，也不存在任何文件里**：它是
每次登录时腾讯服务器在登录流程中下发给客户端的，客户端只把它放在
内存中使用，进程一关就没了。磁盘上只有数据库文件本身和文件头里的
盐（salt）；对 PC 版 QQNT 来说，不存在从磁盘材料离线推导钥匙的
公开公式。所以只要 QQ 还登录着，钥匙就必然在它的进程内存里——
取钥的唯一可行路径是读内存。

> 注意：本工具**不读 `login.db`**、不用账号密码、不做任何协议登录。

### 取钥：扫描 + 密码学验真

`scan_key.py` 按公开算法（QQBackup / x_key_scanner 项目）实现：

- 以 SQLCipher 编解码表里的锚点字符串 `\x09HMAC_SHA1` 定位候选
  区域，围绕锚点及其密集簇收集 16 字节、16 对齐、全可打印且含符号
  的候选窗口；
- 普通路径找不到时，`strong_scan.py` 对全部匿名可写内存做多轮
  全扫（16/8/4 对齐逐级放宽）；
- **每个候选都必须通过密码学验证才算数**：把候选当作 passphrase，
  按 KDF 派生后校验数据库副本第 1 页的 HMAC，对不上立刻丢弃。
  所以扫描只会“找不到”，不会“找错”。

验证参数（3.2.34 实测，两个库一致）：passphrase 为 16 字节 ASCII
串；KDF = PBKDF2-HMAC-SHA512、4000 次；页 HMAC = SHA1；MAC 覆盖自
页内偏移 16 起；每页保留区 48 字节。`qq_crypto.detect_algo()` 会在
副本上自动探测（页 HMAC × KDF 哈希 × MAC 起点）的组合，不写死。

### 解密的坑：WAL 不能按标准算法合并

QQNT 的库带一个 1024 字节自定义头（`SQLite header 3\0`），其后才
是 SQLCipher 流。更麻烦的是增量日志（WAL）：**3.2.34 的 WAL 帧
校验和与两种标准算法都不一致**，按校验和门控会把所有帧拒掉、
盲目全套又会把库套坏。本工具的做法是：只按 **WAL 头盐代际 +
提交边界**过滤帧，解密后合并，并用 `PRAGMA integrity_check`
兜底校验，校验不过就退回只用主库重解。细节见 `qq_crypto.py` 中
`select_wal_frames()` 的注释。

### 文本从哪来

- 群消息优先查 `group_msg_fts.db` 的 FTS 内容表：其中的 **41701
  列是展平后的纯文本正文**，按消息 ID（40001）与主库关联；
- FTS 缺失时，解析 `nt_msg.db` 的 40800 字段 protobuf：repeated
  的 ElementWire 里，字段 45002 是元素类型（1=文本、2=图片……），
  45101 是文本，45105 是 @ 的目标 uid——@ 目标和非文本元素类型
  **永远**从这里取，保证 @ 判定精确。

### 增量与水位线

`patrol_pull.py` 在工作目录维护 `watermark.json`（每类消息已输出
的最大 (发送时间, 消息 ID)）。首次运行只把水位线初始化到当前
最大值、**不倒灌历史**；水位线在输出打印完成后才推进。钥匙失效
（如 QQ 重新登录换钥）时，它会自动调用内存扫描器重取钥并重试
一次，再失败输出 `KEY_FAIL`（退出码 3），不会静默失效。

## 使用前你需要准备什么

你需要准备的只有**一台服务器**：

- **一台 Linux 云服务器即可**（在 Ubuntu 22.04 上验证），在上面
  装官方 QQ for Linux **3.2.34**，登录你的账号并保持 QQ 运行
  （主进程为 `/opt/QQ/qq`）；
- **这台服务器的 root 权限**：取钥要读 `/proc/<pid>/mem`，部署
  时由 Muse 使用（当 QQ 以 root 运行时，扫描器同为 root 即
  可直读，不需要改 ptrace_scope）；
- **把这台服务器的 SSH 访问给到你的 Muse**（密钥登录）。

不需要再准备其他机器或环境：Muse 本身就运行在它自己的环
境里，自带定时任务与 SSH 能力，它从它那一端连到你的服务器
完成全部部署。Python 依赖由 Muse 在部署时装好；你只需留
意服务器磁盘：每轮拉取会产生数倍于数据库大小的副本与明文
文件，把工作目录放在空间充足、权限受控（700）的位置。
本工具只读你自己账号在这台服务器上落盘的本地数据。

## 部署步骤

以下步骤是部署的完整清单。在“让 Muse 帮你部署”模式下，
这些步骤由助手代为执行，你只需完成上一节列出的三件事；手
动部署时也可照此清单逐项完成。

1. **部署脚本到 QQ 主机**：把本仓库放到 QQ 主机的工作目录，
   `pip install -r requirements.txt`，工作目录权限设为 700。
2. **运行一次取钥**：把数据库只读复制到工作目录，用
   `scan_key.py`（找不到时用 `strong_scan.py`）扫描正在运行
   的 QQ 进程内存，生成 `key.json`（具体命令见下方"方式二"）。
3. **写你的配置**：`cp config.example.json config.json`，填入
   你的 QQ 号、工作目录等（配置项见"配置"一节）。
4. **验证解密**：用 `parse_proof.py` 对一份解密副本做 sanity
   check（表、行数、最近消息能正常读出），再跑一次
   `patrol_pull.py` 完成水位线初始化（不输出历史）。
5. **接入调度**：在助手侧设定时任务，周期性执行一条 SSH 命
   令拉取（见 [docs/MUSE-INTEGRATION.md](docs/MUSE-INTEGRATION.md)
   与 [examples/patrol-loop.example.md](examples/patrol-loop.example.md)）；
   没有助手环境时，也可以用 cron 直接跑 `patrol_pull.py`。

## 快速上手

```bash
git clone https://github.com/Znger1/qq-reader.git && cd qq-reader
pip install -r requirements.txt
cp config.example.json config.json   # 填入你自己的 QQ 号与昵称
chmod 700 .                          # 工作目录里将存放钥匙与明文库
```

### 方式一：一键增量拉取（推荐）

首次使用前，先按下面“方式二”的第 0–1 步生成 `key.json`（一次性
动作）。之后 `patrol_pull.py` 每轮直接用存储的钥匙解密；仅当
钥匙因 QQ 重新登录而失效时，它才会自动重扫内存取钥并重试。

```bash
# 首次运行：初始化水位线（不输出历史）
python3 patrol_pull.py --user-uin 你的QQ号

# 之后每轮：输出状态行 + 新消息的 JSON 行
python3 patrol_pull.py --user-uin 你的QQ号
```

第一次运行需要工作目录里已有 `key.json`（见“方式二”第 1 步）。
把它的 stdout 接
到你自己的提醒逻辑即可，例如 cron 每 10 分钟一轮：

```cron
*/10 * * * * cd /path/to/qq-reader && python3 patrol_pull.py >> pull.log 2>&1
```

> 说明：JSON 行的推荐去向是 AI 助手的定时任务——助手通过一
> 条 SSH 命令拉取、读状态行与消息行，后续处理由你自行定义。
> 本仓库包含这套接入的连接机制文档与最小循环规格：见
> [docs/MUSE-INTEGRATION.md](docs/MUSE-INTEGRATION.md) 与
> [examples/patrol-loop.example.md](examples/patrol-loop.example.md)。
> 上面的 cron 示例只是无助手环境时的最简用法。

### 方式二：手动分步

```bash
# 0) 先把库只读复制到你的工作目录（示例）
NTDB=$(echo ~/.config/QQ/nt_qq_*/nt_db)
cp "$NTDB"/{nt_msg.db,nt_msg.db-wal,nt_msg.db-shm,settings.db*} ./

# 1) 取钥：先找 QQ 主进程 pid（映射 wrapper.node 的那个）
#    普通路径
python3 scan_key.py --pids <PID> --settings settings.db \
    --msgdb nt_msg.db --out key.json
#    找不到时用强力全扫
python3 strong_scan.py --pid <PID> --settings settings.db \
    --msgdb nt_msg.db --out key.json

# 2) 解密一个库副本为明文 SQLite
python3 decrypt_db.py --db nt_msg.db --wal nt_msg.db-wal \
    --key key.json --out nt_msg.plain.db

# 3) 看看解出来的库：表、行数、最近几条群消息
python3 parse_proof.py --db nt_msg.plain.db --latest 5
```

### 搜索所有提到你的消息

```bash
python3 mention_search.py --user-uin 你的QQ号 --user-name 你的昵称
```

在全部已存消息里分三类输出：A = 正式 @ 到你的；B = 正文写了你
名字但没正式 @ 的；C = @全体成员（只给总数与最近 10 条）。它用
独立的副本与输出目录，不动水位线，可与增量拉取并行使用。

## 配置

优先级：命令行参数 > 环境变量 > `<workdir>/config.json` > 默认值。

| 配置项 | CLI | 环境变量 | config.json | 默认 |
|---|---|---|---|---|
| 工作目录 | `--workdir` | `QQ_READER_WORKDIR` | — | 脚本所在目录 |
| QQ 号 | `--user-uin` | `QQ_READER_UIN` | `user_uin` | 无（@ 我判定关闭） |
| 昵称 | `--user-name`（仅 mention_search） | `QQ_READER_NAME` | `user_name` | 无（B 类关闭） |
| QQ 配置目录 | `--qq-home` | `QQ_READER_QQ_HOME` | `qq_home` | `~/.config/QQ` |
| 时区偏移 | `--tz-offset` | — | `tz_offset_hours` | 8 |

数据文件都放在工作目录：`key.json`（钥匙，600 权限）、
`watermark.json`、`group_map.json`（群号→群名，由 group_info.db
自动维护）、`identity.json`（你的 uin/uid 缓存）、`runs/`（每轮
的工作副本，仅保留最近 2 轮）。

## 安全设计

- **结构性只读**：整条管线没有发送/修改消息的代码路径；QQ 的
  源文件只被 `read`/`copy`，从不以 SQLite 方式打开、从不写入
  （已实测核验源目录零写入）。
- **零网络代码**：所有脚本不含任何网络功能；运行时不向腾讯或
  任何服务器发出信号，不建立第二个登录会话。
- **不碰凭据**：不读 `login.db`、不使用账号密码、不做协议登录。
  钥匙与账号密码无关——拿到它也只能解密本地库，不能登录账号、
  不能发消息。
- **进程安全**：扫描器用 `pread` 直读 `/proc/<pid>/mem`，不
  attach、不注入、不暂停目标进程；逐区读、逐区释放，并建议在
  `ulimit -v` 硬顶下运行（`patrol_pull.py` 自动取钥时已内置），
  避免在小内存机器上膨胀。
- **副本验证优先**：所有候选钥匙、所有解密结果都先在副本上用
  HMAC / `integrity_check` 验证，验证不过就丢弃或报错。

## ⚠️ 安全与隐私须知（务必读）

- **`key.json` 等于你的全部本地聊天记录的钥匙**。把它和解密后
  的明文库（`*.plain.db`）像密码一样保管：只放在权限 700 的
  目录里，文件 600，不要同步到网盘、不要发给任何人。
- **永远不要把 `key.json`、任何 `*.db`、`watermark.json`、
  `group_map.json`、`identity.json` 提交到 git**——本仓库的
  `.gitignore` 已覆盖这些，但 fork 或改名时请再检查一遍。
  一旦推上公开仓库，即使随后删除，记录也可能已被爬取。
- `mention_search.py` 的输出包含你的真实聊天内容，同样按敏感
  数据处理。

## 免责声明

- 本工具**仅供读取你自己账号在本机上的本地数据**（个人备份、
  检索、自动化提醒等场景）。请勿用于读取他人的数据。
- 本项目与腾讯无关，未获腾讯授权或认可。QQNT、QQ 是腾讯的
  商标。
- 绕过 QQ 本地数据库的加密、读取其内部数据格式，可能违反
  《QQ 软件许可及服务协议》等条款（包括但不限于禁止逆向工程、
  禁止使用非官方手段访问数据的约定），**使用风险由使用者自行
  承担**；作者不对账号封禁、数据损坏或其他任何后果负责。
- 本软件按 MIT 许可证以“现状”提供，不附带任何保证。

## 已知局限

- 仅在 Linux QQ **3.2.34** 上验证；QQ 升级后文件格式、钥匙存放
  位置、KDF 参数都可能变化（参数探测能吸收一部分变化，钥匙
  位置变化则需要更新扫描策略）。
- 图片、文件、语音等非文本内容不在数据库正文里（只有占位与
  元数据），本工具只能报出“这是一条图片/文件消息”，看不到
  内容本身。
- QQ 掉线期间没有同步到本地的消息，库里不存在，自然读不到。
- 系统提示类消息（入群、撤回等 gray-tip）没有单一正文字段，
  只能报类型。
- QQ 每次重新登录，服务器会重新下发钥匙，新旧钥匙可能不同；
  旧钥匙失效时需要重新扫描内存取钥（自动，约几分钟）。

## 方法论出处

本工具为独立实现，方法论来自公开资料并交叉验证：内存取钥的
锚点/簇扫描思路来自 QQBackup 组织的开源项目 x_key_scanner；
SQLCipher 参数（PBKDF2-HMAC-SHA512 × 4000、页 HMAC SHA1）与
NapCatQQ 的开源数据库代码、QQBackup 的公开文档相互印证；消息
表的字段语义来自社区公开的 QQNT 数据库文档。未使用 WeQ、
NapCat 等第三方工具的代码或二进制（WeQ 经评估后未采用：它并
非只读工具、自带协议登录、且核心组件闭源）。

## License

MIT，见 [LICENSE](LICENSE)。
