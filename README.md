# WireGuard 密钥管理工具

一个 Windows 桌面小工具：**填服务器 IP → SSH 连上去 → 可视化查看 / 新增 / 删除 WireGuard 客户端密钥**，不用再手敲 `wg`、`wg-quick`，也不用登上去编辑 `wg0.conf`。

![界面截图](build_assets/exe_screenshot.png)

[![Build](https://github.com/leirui2/wireguard-manage/actions/workflows/build.yml/badge.svg)](https://github.com/leirui2/wireguard-manage/actions/workflows/build.yml)

### ⬇️ 直接下载

| 版本 | 下载 | 说明 |
|---|---|---|
| **最新构建** | **[WireGuardManager.exe](https://github.com/leirui2/wireguard-manage/releases/latest/download/WireGuardManager.exe)** | 每次推送到 `main` 自动重新打包，链接永久不变 |

SHA256 校验值见同一发行版下的 [SHA256.txt](https://github.com/leirui2/wireguard-manage/releases/latest/download/SHA256.txt)。

> Windows 10 / 11 64 位，双击即用，**不需要安装 Python 或任何运行库**。
> 也可以到 [Releases 页面](https://github.com/leirui2/wireguard-manage/releases) 查看历史版本。

---

## 功能特性

| 功能 | 说明 |
|---|---|
| **查看密钥** | 自动列出所有 `[Peer]`，显示备注名、公钥、VPN 地址、最近握手、上下行流量、来源端点、在线状态 |
| **新增密钥** | 自动分配空闲 IPv4/IPv6 地址 → 生成密钥对 → 写入 `[Peer]` → 热加载 → 生成客户端 `.conf` |
| **删除密钥** | 多选后二次确认，同时从配置和运行时移除 |
| **备注管理** | 名称/备注以注释形式存在 `[Peer]` 上方，换设备、换工具都不会丢 |
| **自动探测部署** | 自动找 `wg`、`/etc/wireguard/*.conf`、活动接口、服务端公钥、监听端口、允许网段、DNS |
| **密码 / 私钥双认证** | 支持 SSH 密码，也支持 OpenSSH / PEM 私钥（可带口令）；sudo 密码可单独填 |
| **多服务器** | 记住连接过的服务器（**只存主机/端口/用户名/私钥路径，不存任何密码**） |

### 兼容性

- **标准 `wg-quick` 部署**：完全支持（包括 `angristan/wireguard-install` 这类一键脚本，它最终也是标准 `wg0.conf`）
- **Docker / wg-easy**：会尝试 `docker exec` 进容器读写；但 wg-easy 新版本可能改用数据库管理客户端，直接改文件未必生效，**请先在测试环境验证**
- **配置路径不在默认位置**：可在「高级设置」里手动指定配置文件绝对路径和接口名

---

## 快速开始

### 方式一：直接用 exe（推荐给最终用户）

1. 下载 [WireGuardManager.exe](https://github.com/leirui2/wireguard-manage/releases/latest/download/WireGuardManager.exe)
   （或到 [Releases](../../releases) 页面挑历史版本）
2. 放到**有写权限的目录**（桌面、D 盘、U 盘都行，**不要放 `C:\Program Files`**）
3. 双击运行

目标电脑**不需要安装 Python 或任何依赖**，exe 已自带解释器、Tcl/Tk、OpenSSL 和 SSH 库。

> 仅支持 64 位 Windows 10 / 11。

### 方式二：源码运行（开发/调试）

需要 **Python 3.10+，且自带 tkinter**（Windows 官方安装包默认包含）。

```bat
双击 启动工具.bat
```

首次运行会自动把 `paramiko` 装到项目内的 `vendor\` 目录（需联网），不污染系统 Python。

也可以手动执行：

```bat
python -m pip install --target vendor paramiko==5.1.0
set PYTHONPATH=%CD%;%CD%\vendor
python main.py
```

### 方式三：自己打包 exe

```bat
双击 打包exe.bat
```

约 45 秒，产物在 `dist\WireGuard密钥管理工具.exe`。打包环境是项目内的 `.build-venv\`，首次使用需先创建：

```bat
python -m venv .build-venv
.build-venv\Scripts\python.exe -m pip install pyinstaller==6.22.3 paramiko==5.1.0
```

---

## 使用说明

### 1. 连接

| 字段 | 说明 |
|---|---|
| 服务器 IP | 公网或内网地址都行。填内网地址时，工具会自动把客户端 `Endpoint` 换成服务器公网 IP |
| SSH 端口 | 默认 22，改过就填实际端口 |
| 用户名 | 推荐 `root`；普通账号需要 sudo 权限（见下） |
| 认证方式 | 密码 或 私钥文件 |
| 私钥口令 | 私钥没加密就留空 |
| **sudo 密码** | **非 root 账号必填**。密码登录时可留空（默认复用 SSH 密码）；私钥登录时一定要单独填 |

点「连接」后，工具会自动探测并显示：接口名、配置文件路径、监听端口、VPN 网段、DNS、服务端公钥。

> 读取 `/etc/wireguard/wg0.conf` 通常需要 root（该目录一般是 `700`）。
> 普通账号要么在连接区填 **sudo 密码**，要么让管理员配置免密 sudo（`NOPASSWD`）。

### 2. 查看

列表默认显示名称、备注、公钥前缀、VPN 地址、最近握手、流量、来源端点、在线状态。
**5 分钟内有握手即视为在线**。双击某一行可以看完整公钥。

### 3. 新增密钥

点「＋ 新增密钥」，填写：

- **密钥名称**（必填，例如 `张三-手机`）
- 备注（选填，例如 `研发部 / 2026年入职领用`）
- 客户端 `AllowedIPs`（默认 `0.0.0.0/0, ::/0`，即全局代理）
- DNS（默认取自服务端配置）
- Endpoint（默认 SSH 的 IP + 监听端口）
- 指定 VPN 地址（留空 = 自动分配）
- 是否使用 `PresharedKey`（默认跟随现有密钥的惯例）

生成后会弹出客户端 `.conf` 全文，可复制或另存，并默认保存到 `clients\` 目录。

> ⚠️ **客户端私钥只会出现这一次**。服务端只保存公钥，之后无法重新导出，请务必保存 `.conf`。

### 4. 删除密钥

选中一行或多行（`Ctrl` / `Shift` 多选）→「删除选中」→ 二次确认。

### 5. 高级设置

探测不准时（例如配置不在 `/etc/wireguard`），手动指定：

- 配置文件绝对路径
- 接口名（如 `wg0`）
- 客户端 Endpoint 主机（当 SSH 地址与 VPN 入口地址不同时）

---

## 安全设计

这个工具会**改写服务器的 WireGuard 配置**，所以每一步都做了保护：

```
备份 wg0.conf
   ↓
写临时文件（umask 077）
   ↓
cp + mv 原子替换（不会出现半截文件）
   ↓
wg-quick strip + wg syncconf 热加载（不中断现有连接）
   ↓
回读文件校验 + 运行时公钥核对
   ↓
任何一步失败 → 自动恢复备份并重新加载
```

其他措施：

- **逐字保留未改动内容**：`PostUp` / `PostDown` / `MTU` / 注释 / 未知字段都不动，只增删目标 `[Peer]` 段
- **`SaveConfig = true` 会警告**：wg-quick 停服时可能按运行时状态重写配置，覆盖备注注释
- **SSH 主机指纹 TOFU**：首次连接记录指纹到 `known_hosts`，之后指纹变化直接拒绝连接，防中间人
- **私钥不出现在命令行**：`wg pubkey` 通过 stdin 读取，`wg-quick strip` 的临时文件设为 `600`
- **日志脱敏**：`PrivateKey` / `PresharedKey` / `password` 一律替换为 `***`
- **不保存密码**：`connections.json` 只存主机、端口、用户名、认证方式、私钥路径

---

## 数据文件

工具运行时会在 **exe 所在目录**（源码运行时是项目根目录）生成：

| 文件 | 内容 | 是否含敏感信息 |
|---|---|---|
| `connections.json` | 连接过的服务器：主机、端口、用户名、私钥路径 | 有服务器地址，**无密码** |
| `known_hosts` | SSH 主机指纹 | 有服务器地址 |
| `clients\*.conf` | 导出给客户端的配置，**含客户端私钥** | **是，注意保管** |
| `error.log` | 仅启动崩溃时生成 | 可能含路径 |

**这三个都已在 `.gitignore` 中排除，不会被提交到仓库。**

工具本身不联网、不上报任何数据，只在你点「连接」时通过 SSH 直连你的服务器。

---

## 目录结构

```
wireguard-manage/
├── main.py                    # 入口（兼容源码运行与 exe）
├── wgmanager/
│   ├── gui.py                 # tkinter 界面、对话框、线程调度
│   ├── backend.py             # SSH / Docker / 演示服务器三种后端
│   ├── probe.py               # 部署方式自动探测 + 错误诊断
│   ├── config.py              # wg0.conf 保真解析与改写
│   ├── service.py             # 增删查、备份/热加载/回滚
│   └── util.py                # 密钥生成、IP 分配、格式化
├── tests/test_core.py         # 19 个单元测试（含模拟服务器）
├── build_assets/              # 图标、版本信息、界面截图
├── wireguard-manager.spec     # PyInstaller 打包配置
├── requirements.txt           # 运行时依赖
├── 启动工具.bat                # 源码一键启动
├── 打包exe.bat                 # 一键打包 exe
└── .github/workflows/build.yml # 推送到 GitHub 自动构建
```

---

## 常见问题

**Q：连接时报「没有找到 WireGuard 配置文件」**
先看是不是权限问题。`/etc/wireguard` 通常是 `700 root`，普通用户读不到。
在连接区填「sudo 密码」，或改用 `root` 登录。工具会把「无 sudo 权限 / 权限被拒 / 目录不存在」分开提示。

**Q：报「sudo 密码校验失败」**
该账号不在 `sudoers` 里，或密码不对。可以改用 `root`，或让管理员加 `NOPASSWD`。

**Q：新增密钥后客户端连不上**
检查三件事：① 客户端 `.conf` 里的 `Endpoint` 是公网可达的地址和端口；② 服务器防火墙放行了 **UDP** 监听端口；③ 云厂商安全组同样要放行 UDP。

**Q：`wg-easy` / Docker 部署能用吗**
会尝试进容器读写，但新版 wg-easy 用数据库管理客户端，直接改文件可能不生效。建议先测试，或改用「手动指定配置路径」。

**Q：exe 被杀软拦截**
PyInstaller 打包的程序没有代码签名，容易被误报。添加信任即可；介意的话可以自行用源码运行。

**Q：exe 首次启动慢**
单文件模式需要先把运行库解压到 `%TEMP%`，约 2~4 秒。需要秒开可以改用目录模式打包。

---

## 自动构建与发布

推送到 `main` 分支、打 `v*` 标签，或在 Actions 页面手动触发时，GitHub Actions 会在 `windows-latest` 上：

1. 安装 Python 3.13 与依赖
2. 跑一遍单元测试（不通过就不打包）
3. 用 `wireguard-manager.spec` 打包单文件 exe
4. 校验产物体积、计算 SHA256
5. **自动发布到 Releases** 并附上 exe 与校验值

发布规则：

| 触发方式 | 结果 |
|---|---|
| 推送到 `main` | 更新滚动发行版 **`latest`**（同名资产覆盖，仓库里始终只有一条，下载链接永久固定） |
| 推送 `v1.0.0` 这类标签 | 新建对应版本的正式发行版，自动生成变更说明 |
| 手动 Run workflow | 同推送到 `main` |

同时在 Actions 里保留一份 Artifact（30 天）。

整个流程**不需要任何 Secrets**（用的是仓库自带的 `GITHUB_TOKEN`），也不需要你在页面上点任何按钮。

> 注意：exe 放在 **Releases**，不是右侧的「包 / Packages」。
> Packages 只接收 npm / Maven / NuGet / Docker 这类包格式，不接受任意二进制文件。

---

## 开发与测试

```bat
python -m unittest discover -s tests -v
```

测试使用内存模拟服务器（`DemoBackend`），不依赖真实环境，覆盖：配置保真解析、部署探测、增删密钥、重名拒绝、手动指定 IP、热加载失败自动回滚、sudo 命令构造、窗口居中。

界面里勾选「演示模式」也能不接服务器直接试用全部流程。

---

## 免责声明

本工具会直接修改远程服务器上的 WireGuard 配置。虽然内置了备份与自动回滚，**仍建议先在测试环境验证**，并自行确保有其它方式登录服务器（避免误操作后失联）。

请遵守所在地区法律法规，仅用于自己拥有或已获授权的服务器。
