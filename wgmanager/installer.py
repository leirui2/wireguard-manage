"""在服务器上一键安装 WireGuard 服务端。

流程（每一步都可单独失败、都有明确报错）：

    检测发行版 -> 装包 -> 生成服务端密钥 -> 写 /etc/wireguard/wg0.conf
    -> 开 IP 转发 -> 启动 wg-quick@<iface> -> 回读校验

两条硬性约束：

* **绝不覆盖已存在的配置文件**。发现目标路径已有文件就直接中止，
  把决定权交回给用户（他可能只是想改路径，不是想重装）。
* 服务端私钥只通过 stdin 传递，不写进命令行、不写进日志；落盘权限 600。

只做「最小可用」部署：C 端能连上、能把流量转发出公网。不做 DNS 服务器、
不做网页后台、不碰已有防火墙规则（除非用户明确勾选放行端口）。
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import shlex
from dataclasses import dataclass, field

from .backend import Backend
from .util import is_wg_key


def _q(text: str) -> str:
    return shlex.quote(str(text))


def _root_chain(chain: str) -> str:
    """整串包进 sh -c，保证 sudo 作用于 && 后面的每一条。"""
    return "sh -c " + shlex.quote(chain)


# ---------------------------------------------------------------- 发行版识别

DEBIAN_IDS = {
    "debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali", "deepin",
    "uos", "neon", "devuan", "armbian",
}
RHEL_IDS = {
    "rhel", "centos", "fedora", "rocky", "almalinux", "ol", "oracle",
    "tencentos", "anolis", "openeuler", "kylin", "cloudlinux", "springdale",
}
ARCH_IDS = {"arch", "manjaro", "endeavouros", "garuda", "artix"}
SUSE_IDS = {"opensuse-leap", "opensuse-tumbleweed", "suse", "opensuse", "sles"}


@dataclass
class Platform:
    distro_id: str = ""
    name: str = ""
    family: str = "unknown"
    install_cmd: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.name or self.distro_id or "未知发行版"

    @property
    def supported(self) -> bool:
        return bool(self.install_cmd)


def parse_os_release(text: str) -> dict:
    data: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def _major_version(version: str) -> int:
    match = re.match(r"\s*(\d+)", version or "")
    return int(match.group(1)) if match else 0


def platform_from_release(info: dict) -> Platform:
    distro = (info.get("ID") or "").strip().lower()
    likes = (info.get("ID_LIKE") or "").strip().lower().split()
    name = (info.get("PRETTY_NAME") or info.get("NAME") or distro).strip()
    version = (info.get("VERSION_ID") or "").strip()
    family = "unknown"
    for candidate in [distro] + likes:
        if candidate in DEBIAN_IDS:
            family = "debian"
            break
        if candidate in RHEL_IDS:
            family = "rhel"
            break
        if candidate in ARCH_IDS:
            family = "arch"
            break
        if candidate in SUSE_IDS:
            family = "suse"
            break

    plat = Platform(distro_id=distro, name=name, family=family)
    if family == "debian":
        major = _major_version(version)
        too_old = (distro == "debian" and 0 < major < 11) or (
            distro == "ubuntu" and 0 < major < 20
        )
        if too_old:
            # 这些版本的主仓库里没有能用的 wireguard 包（Debian 10 在 backports，
            # Ubuntu 18.04 的内核 4.15 根本没有模块），自动装必然失败在半路。
            plat.install_cmd = ""
            if distro == "debian":
                plat.notes.append(
                    f"Debian {version} 的内核 4.19 不自带 WireGuard 模块，"
                    "官方要求先启用 backports 再安装（bullseye 及更新版本才开箱可用），"
                    "工具不会自动改软件源。\n"
                    "手动做法：加一行 `deb http://deb.debian.org/debian "
                    f"{'buster' if major == 10 else 'stretch'}-backports main` 到 "
                    "/etc/apt/sources.list，`apt update` 后安装 wireguard 并升级内核。\n"
                    "如果内核已经升到 5.6 以上，也可以直接 `apt install wireguard` 后回来连接。"
                )
            else:
                plat.notes.append(
                    f"Ubuntu {version} 的内核（4.15）不自带 WireGuard 模块，"
                    "需要先安装 HWE 内核（如 linux-generic-hwe-18.04）。\n"
                    "升级内核并重启后，`apt install wireguard` 再回来连接即可。"
                )
        else:
            plat.install_cmd = _root_chain(
                "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard"
            )
    elif family == "rhel":
        major = _major_version(version)
        if distro == "fedora" or major >= 9:
            # RHEL 9 / CentOS Stream 9 / Rocky 9 / Alma 9 / Fedora：
            # wireguard-tools 在官方 AppStream 仓库，内核 5.14+ 自带模块，不需要 EPEL。
            plat.install_cmd = _root_chain(
                "dnf install -y wireguard-tools || yum install -y wireguard-tools"
            )
        elif major == 8:
            # RHEL 8 系内核 4.18 没有 wireguard 模块，wireguard-tools 只在 EPEL。
            # 官方给的做法就是 EPEL + ELRepo 的 kmod-wireguard + wireguard-tools。
            plat.install_cmd = _root_chain(
                "dnf install -y "
                "https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm "
                "https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm"
                " && dnf install -y kmod-wireguard wireguard-tools"
            )
            plat.notes.append(
                "RHEL / CentOS / Rocky / Alma 8 的内核 4.18 不含 WireGuard 模块，"
                "需要 ELRepo 的 kmod-wireguard；安装过程会额外引入 EPEL 与 ELRepo 两个第三方仓库。"
            )
        elif major and major <= 7:
            plat.install_cmd = ""
            plat.notes.append(
                f"{name} 的内核 3.10 不含 WireGuard 模块，且 CentOS 7 已于 2024-06 停止维护、"
                "软件源多已下线，不做自动安装。\n"
                "手动做法：安装 epel-release 与 elrepo-release，"
                "再 exec `yum install -y kmod-wireguard wireguard-tools`，然后重新连接。"
            )
        else:
            # 版本号读不出来，按新版本处理（先试官方仓库，失败再试 yum）
            plat.install_cmd = _root_chain(
                "dnf install -y wireguard-tools || yum install -y wireguard-tools"
            )
    elif family == "arch":
        # Arch 官方明确不支持部分升级：绝不能用 pacman -Sy 单独装包，
        # 否则可能把 glibc 之类的依赖升一半，连 sudo 都起不来。
        plat.install_cmd = "pacman -S --needed --noconfirm wireguard-tools"
        plat.notes.append(
            "Arch 不支持部分升级，这里只用 pacman -S（不刷新数据库）。"
            "如果提示找不到包或下载 404，请先在服务器上手动执行 pacman -Syu，再重试。"
        )
    elif family == "suse":
        plat.install_cmd = "zypper --non-interactive install wireguard-tools"
    else:
        plat.notes.append(
            "没能识别发行版，无法自动装包。可先手动安装：\n"
            "  Debian/Ubuntu   apt install wireguard\n"
            "  RHEL/Fedora     dnf install wireguard-tools\n"
            "  Arch            pacman -S wireguard-tools\n"
            "  openSUSE        zypper install wireguard-tools\n"
            "  Alpine          apk add -U wireguard-tools"
            "（3.19 之前还要装 wireguard-tools-wg-quick 子包）\n"
            "装好后再重新连接，就能直接管理已有部署。"
        )
    return plat


def detect_platform(target: Backend) -> Platform:
    res = target.run("cat /etc/os-release", root=True, timeout=15)
    info = parse_os_release(res.out if res.ok else "")
    if not info:
        res = target.run("cat /usr/lib/os-release", root=True, timeout=15)
        info = parse_os_release(res.out if res.ok else "")
    return platform_from_release(info)


# ---------------------------------------------------------------- 方案

#: 自动选网段时的候选池（都是私网大段里的小段）
SUBNET_POOL = [f"10.{n}.0.0/24" for n in range(8, 31)] + ["172.20.0.0/24", "192.168.88.0/24"]


@dataclass
class Options:
    iface: str = "wg0"
    subnet: str = ""            # 空 = 自动挑一个不冲突的
    listen_port: int = 0        # 0 = 自动挑
    endpoint_host: str = ""
    enable_forward: bool = True  # 开 IP 转发（客户端才能上网）
    enable_nat: bool = True      # 写 iptables MASQUERADE 规则
    open_firewall: bool = False  # 放行 UDP 端口（只针对 ufw/firewalld）


@dataclass
class Plan:
    platform: Platform
    iface: str = "wg0"
    conf_path: str = "/etc/wireguard/wg0.conf"
    subnet: str = "10.8.0.0/24"
    server_address: str = "10.8.0.1/24"
    listen_port: int = 51820
    endpoint_host: str = ""
    default_iface: str = ""
    firewall: str = ""          # ufw | firewalld | ""
    nat_method: str = ""        # iptables | firewalld | ""
    forward_enabled: bool = False
    steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class InstallResult:
    public_key: str = ""
    conf_path: str = ""
    iface: str = ""
    started: bool = False
    warnings: list[str] = field(default_factory=list)
    message: str = ""


def _existing_networks(target: Backend) -> list[ipaddress._BaseNetwork]:
    res = target.run("ip -4 route show", root=True, timeout=15)
    nets: list[ipaddress._BaseNetwork] = []
    for line in res.out.splitlines():
        token = line.split()[0] if line.split() else ""
        if not token or token in {"default", "broadcast", "local", "unreachable"}:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return nets


def _pick_subnet(target: Backend, wanted: str = "") -> tuple[str, str]:
    if wanted.strip():
        net = ipaddress.ip_network(wanted.strip(), strict=False)
        if net.version != 4:
            raise ValueError("目前只支持用 IPv4 网段做 VPN 内网")
        if net.prefixlen > 30:
            raise ValueError("网段太小了，至少要能放下服务端 + 客户端，建议用 /24")
        return str(net), f"{net.network_address + 1}/{net.prefixlen}"

    used = _existing_networks(target)
    for candidate in SUBNET_POOL:
        net = ipaddress.ip_network(candidate)
        if any(net.overlaps(other) for other in used if other.version == 4):
            continue
        return candidate, f"{net.network_address + 1}/{net.prefixlen}"
    raise ValueError("10.x 网段全被占用了，请在「高级设置」里手动指定 VPN 网段")


def _port_in_use(target: Backend) -> set[int]:
    res = target.run("ss -lun", root=True, timeout=15)
    ports: set[int] = set()
    for line in res.out.splitlines():
        parts = line.split()
        for token in parts:
            match = re.search(r":(\d+)$", token)
            if match:
                ports.add(int(match.group(1)))
                break
    return ports


def _pick_port(target: Backend, wanted: int = 0) -> int:
    used = _port_in_use(target)
    if wanted:
        if wanted in used:
            raise ValueError(f"UDP 端口 {wanted} 已被占用，请换一个")
        return wanted
    for port in range(51820, 51841):
        if port not in used:
            return port
    raise ValueError("51820-51840 都被占用了，请手动指定监听端口")


def _default_iface(target: Backend) -> str:
    res = target.run("ip -4 route show default", root=True, timeout=15)
    for line in res.out.splitlines():
        parts = line.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return ""


def _tool_paths(target: Backend, names: list[str]) -> dict[str, bool]:
    """一次往返确认多个命令是否存在。

    不能直接用 `command -v`：非 root 用户的 PATH 里通常没有 /usr/sbin，
    而 iptables / firewall-cmd 恰恰都装在那里，会误判成「没装」。
    """
    checks = " ".join(
        f'if command -v {name} >/dev/null 2>&1 || [ -x /usr/sbin/{name} ] '
        f'|| [ -x /sbin/{name} ]; then echo "HAVE:{name}"; fi;'
        for name in names
    )
    res = target.run("sh -c " + shlex.quote(checks), root=True, timeout=20)
    found: dict[str, bool] = {}
    for line in (res.out or "").splitlines():
        line = line.strip()
        if line.startswith("HAVE:"):
            found[line[5:].strip()] = True
    return found


def _firewall(target: Backend, tools: dict[str, bool]) -> str:
    if tools.get("ufw"):
        status = target.run("ufw status", root=True, timeout=15)
        if "status: active" in (status.out or "").lower():
            return "ufw"
    if tools.get("firewall-cmd"):
        state = target.run("firewall-cmd --state", root=True, timeout=15)
        if "running" in (state.out or "").lower():
            return "firewalld"
    return ""


def _nat_method(tools: dict[str, bool], firewall: str) -> str:
    """决定用谁来配 NAT。

    firewalld 在跑就必须交给它管：Red Hat 明确要求 firewalld / nftables / iptables
    只用一个，混着写规则会被 firewalld reload 清掉。
    否则用 iptables（Debian/Ubuntu/openSUSE 的标准做法）。
    两者都没有就不写 PostUp —— 写了也必然让 wg-quick up 失败。
    """
    if firewall == "firewalld" and tools.get("firewall-cmd"):
        return "firewalld"
    if tools.get("iptables"):
        return "iptables"
    return ""


def _forward_enabled(target: Backend) -> bool:
    res = target.run("sysctl -n net.ipv4.ip_forward", root=True, timeout=10)
    return (res.out or "").strip() == "1"


def _iface_exists(target: Backend, iface: str) -> bool:
    res = target.run("ip -br link show", root=True, timeout=15)
    for line in (res.out or "").splitlines():
        parts = line.split()
        if parts and parts[0].rstrip(":") == iface:
            return True
    return False


def has_systemd(target: Backend) -> bool:
    """自动安装靠 systemctl 起服务，没有 systemd 的系统（Alpine/Devuan/容器）必须提前拦下。"""
    res = target.run("command -v systemctl", timeout=10)
    if not (res.ok and (res.out or "").strip()):
        return False
    pid1 = target.run("cat /proc/1/comm", root=True, timeout=10)
    comm = (pid1.out or "").strip()
    return comm in {"", "systemd"}


def build_plan(target: Backend, options: Options, endpoint_host: str = "") -> Plan:
    """只做只读探测，不修改服务器。"""
    plat = detect_platform(target)
    plan = Plan(platform=plat, iface=options.iface or "wg0", endpoint_host=endpoint_host)
    plan.conf_path = f"/etc/wireguard/{plan.iface}.conf"
    plan.subnet, plan.server_address = _pick_subnet(target, options.subnet)
    plan.listen_port = _pick_port(target, options.listen_port)
    plan.default_iface = _default_iface(target)
    tools = _tool_paths(target, ["iptables", "firewall-cmd", "nft", "ufw"])
    plan.firewall = _firewall(target, tools)
    plan.nat_method = _nat_method(tools, plan.firewall)
    plan.forward_enabled = _forward_enabled(target)

    net = ipaddress.ip_network(plan.subnet)

    # 没有 systemd 就别往下走了：装完包、写完配置却起不来服务，
    # 会把服务器留在半装状态，比直接拒绝更糟。
    if not has_systemd(target):
        plan.platform.install_cmd = ""
        plan.platform.notes = [
            "这台机器没有在用 systemd（Alpine / Devuan / OpenRC，或本身跑在容器里），"
            "自动安装没法把服务拉起来，已在这里停住，不会改动系统。\n"
            f"可以手动装 wireguard-tools 后执行 wg-quick up {plan.iface}，"
            "再用系统自己的 init 加开机自启。",
        ]
    plan.steps = [
        f"安装 WireGuard（{plat.label}）",
        f"生成服务端密钥对",
        f"写入 {plan.conf_path}：网段 {plan.subnet}，服务端 {plan.server_address}，"
        f"UDP {plan.listen_port}",
        "开启 IP 转发（net.ipv4.ip_forward=1，持久化到 /etc/sysctl.d/99-wireguard.conf）"
        if options.enable_forward and not plan.forward_enabled
        else "IP 转发已开启，跳过",
        f"启用并启动 wg-quick@{plan.iface}",
    ]
    if options.enable_nat:
        if plan.nat_method == "iptables":
            plan.steps.insert(
                -1,
                f"写入 NAT 规则（iptables，PostUp）：客户端流量经 {plan.default_iface} 出去"
                if plan.default_iface
                else "写入 NAT 规则（iptables，未能识别默认网卡，配置里会留占位注释）",
            )
        elif plan.nat_method == "firewalld":
            plan.steps.insert(-1, "在 firewalld 里开启 masquerade（实现 NAT）")
        else:
            plan.steps.insert(-1, "跳过 NAT：本机既没有 iptables 命令，firewalld 也没在运行")
    if options.open_firewall and plan.firewall:
        plan.steps.append(
            f"在 {plan.firewall} 放行 UDP {plan.listen_port}"
        )

    # 无论支持与否都要把注意事项带出来：Debian 10 的 backports、
    # RHEL 8 的 EPEL、Arch 的 pacman -Syu 提示，漏掉就会让人踩坑。
    plan.notes.extend(plat.notes)
    if plan.forward_enabled and options.enable_forward:
        pass
    if options.enable_nat and plan.nat_method == "iptables" and not plan.default_iface:
        plan.notes.append(
            "没识别到默认出口网卡，NAT 规则里的 -o 参数会留空占位，可能需要手工改。"
        )
    if options.enable_nat and plan.nat_method == "firewalld":
        plan.notes.append(
            "这台机器在跑 firewalld，NAT 用 firewall-cmd 开启 masquerade（永久生效，"
            "以后关掉接口也不会撤销）。"
        )
    if options.enable_nat and not plan.nat_method:
        plan.notes.append(
            "这台机器既没有 iptables 命令、firewalld 也没在运行，无法自动配置 NAT："
            "客户端能连上但上不了网。装完需要自己用 nft 或 firewalld 配 masquerade。"
        )
    if plan.firewall and not options.open_firewall:
        plan.notes.append(
            f"检测到 {plan.firewall} 已启用。如果客户端连不上，需要放行 UDP {plan.listen_port}，"
            "可以勾选上面的选项，或自行添加规则。"
        )
    if net.prefixlen < 24:
        plan.notes.append(f"网段 /{net.prefixlen} 比较大，注意别和服务器所在内网冲突。")
    if _iface_exists(target, plan.iface):
        plan.notes.append(
            f"接口 {plan.iface} 已经存在（可能是别的 VPN 或上次的残留）。"
            "继续安装会复用这个接口名，请确认不会影响现有连接。"
        )
    return plan


def render_conf(
    private_key: str,
    plan: Plan,
    *,
    enable_nat: bool = True,
    enable_forward: bool = True,
) -> str:
    """生成标准的 wg-quick 配置。

    NAT 只在本机确实有 iptables 时才写成 PostUp：PostUp 由 wg-quick 用 bash 执行，
    任何一条返回非 0 都会让整个 `wg-quick up` 失败，接口起不来。
    没 iptables 的机器（RHEL 9 精简安装、树莓派 Lite 等）宁可不写，也不能写错。
    """
    lines = [
        "# 由 WireGuard 管理台自动创建",
        f"# 创建时间：{__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "[Interface]",
        f"Address = {plan.server_address}",
        f"ListenPort = {plan.listen_port}",
        f"PrivateKey = {private_key}",
    ]
    if enable_nat and plan.nat_method == "iptables" and plan.default_iface:
        out = plan.default_iface
        lines += [
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; "
            f"iptables -A FORWARD -o %i -j ACCEPT; "
            f"iptables -t nat -A POSTROUTING -o {out} -j MASQUERADE",
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; "
            f"iptables -D FORWARD -o %i -j ACCEPT; "
            f"iptables -t nat -D POSTROUTING -o {out} -j MASQUERADE",
        ]
    elif enable_nat and plan.nat_method == "iptables":
        lines += [
            "# 未识别默认出口网卡，下面是占位规则，请手工把 eth0 改成实际网卡后再启用",
            "# PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
            "# PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        ]
    elif enable_nat and plan.nat_method == "firewalld":
        lines.append("# NAT 由 firewalld 的 masquerade 负责，见安装日志")
    elif enable_nat:
        lines.append("# 本机没有 iptables，未写入 NAT 规则；客户端只能访问服务器本身")
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 执行


def _kmod_hint(family: str) -> str:
    if family == "debian":
        return (
            "Debian 10 及更早版本的内核 4.19 不带该模块：需要启用 backports 装上较新的内核，"
            "或改装 DKMS 版本；Ubuntu 则要先装 HWE 内核（如 linux-generic-hwe-22.04）。"
        )
    if family == "rhel":
        return (
            "RHEL / CentOS / Rocky / Alma 8 及更早需要 ELRepo 的 kmod-wireguard，"
            "或者 wireguard-dkms。"
        )
    if family == "arch":
        return "可以试试 wireguard-dkms + 对应内核的 headers 包。"
    if family == "suse":
        return "可以试试 wireguard-kmp-default 之类与内核匹配的模块包。"
    return "可以试着装 wireguard-dkms，或把内核升级到 5.6 以上。"


def run_install(
    target: Backend,
    plan: Plan,
    options: Options,
    log=lambda _m: None,
) -> InstallResult:
    """按方案执行安装。任何一步失败都会抛异常并说明卡在哪。"""
    result = InstallResult(conf_path=plan.conf_path, iface=plan.iface)
    if not plan.platform.supported:
        raise RuntimeError(
            "没能识别发行版或该发行版不支持自动安装。\n" + "\n".join(plan.platform.notes)
        )

    # 1) 目录 + 冲突检查（绝不覆盖已有配置）
    exists = target.run(f"test -e {_q(plan.conf_path)} && echo EXISTS || echo NONE",
                        root=True, timeout=15)
    if "EXISTS" in (exists.out or ""):
        raise RuntimeError(
            f"{plan.conf_path} 已经存在，为安全起见不会覆盖。\n"
            "如果那是残留配置，请先在服务器上备份/移走；"
            "或者回到「高级设置」把配置路径指到它，直接管理已有部署。"
        )
    log("检查通过：目标配置文件不存在，不会覆盖任何已有部署")

    mk = target.run(f"install -d -m 700 /etc/wireguard", root=True, timeout=20)
    if not mk.ok:
        raise RuntimeError(f"创建 /etc/wireguard 目录失败：{mk.err.strip()}")

    # 2) 装包（可能要几十秒）
    log(f"开始安装 WireGuard：{plan.platform.install_cmd}")
    pkg = target.run(plan.platform.install_cmd, root=True, timeout=600)
    if not pkg.ok:
        raise RuntimeError(
            "安装 WireGuard 失败：\n" + (pkg.err.strip() or pkg.out.strip() or "未知原因")
        )
    log("WireGuard 安装完成")

    # 3) 内核模块校验：包只是用户态工具，内核没有 wireguard 模块照样起不来。
    #    这一步放在写配置之前，失败就停手，服务器网络不受任何影响。
    mod = target.run("modprobe wireguard", root=True, timeout=60)
    if not mod.ok:
        raise RuntimeError(
            "WireGuard 软件包已安装，但这台机器的内核没有 wireguard 模块，"
            "写配置也起不来，已在此停住（没有写入任何配置、没有启动服务、没动防火墙）。\n\n"
            + _kmod_hint(plan.platform.family)
            + f"\n\n具体报错：{(mod.err or mod.out).strip()[:400]}"
        )
    log("内核 wireguard 模块加载正常")

    # 4) 生成服务端密钥（私钥只走 stdin，不进命令行）
    gen = target.run("wg genkey", root=True, timeout=20)
    private_key = (gen.out or "").strip().splitlines()
    private_key = private_key[-1].strip() if private_key else ""
    if not is_wg_key(private_key):
        raise RuntimeError("wg genkey 没有返回合法私钥，安装中止")
    pub = target.run("wg pubkey", stdin=private_key + "\n", root=True, timeout=20)
    public_key = (pub.out or "").strip()
    if not is_wg_key(public_key):
        raise RuntimeError("推导服务端公钥失败，安装中止")
    result.public_key = public_key
    log(f"已生成服务端密钥，公钥 {public_key[:12]}…")

    # 5) 写配置：先落临时文件，再以 root 安装成 600
    conf_text = render_conf(private_key, plan, enable_nat=options.enable_nat,
                            enable_forward=options.enable_forward)
    token = secrets.token_hex(6)
    tmp = f"/tmp/.wgmgr_install_{token}.conf"
    write = target.run(f"umask 077 && cat > {_q(tmp)}", stdin=conf_text, timeout=30)
    if not write.ok:
        raise RuntimeError(f"写临时配置失败：{write.err.strip()}")
    moved = target.run(
        _root_chain(
            f"install -m 600 -o root -g root {_q(tmp)} {_q(plan.conf_path)} && rm -f {_q(tmp)}"
        ),
        root=True,
        timeout=30,
    )
    if not moved.ok:
        target.run(f"rm -f {_q(tmp)}", timeout=10)
        raise RuntimeError(f"写入 {plan.conf_path} 失败：{moved.err.strip()}")
    log(f"配置已写入 {plan.conf_path}（权限 600）")

    # 6) IP 转发
    if options.enable_forward and not plan.forward_enabled:
        sysctl_tmp = f"/tmp/.wgmgr_sysctl_{token}.conf"
        sysctl_text = "net.ipv4.ip_forward = 1\n"
        w2 = target.run(f"cat > {_q(sysctl_tmp)}", stdin=sysctl_text, timeout=20)
        if w2.ok:
            mv2 = target.run(
                _root_chain(
                    f"install -m 644 {_q(sysctl_tmp)} /etc/sysctl.d/99-wireguard.conf && "
                    f"rm -f {_q(sysctl_tmp)} && sysctl -q -p /etc/sysctl.d/99-wireguard.conf"
                ),
                root=True,
                timeout=30,
            )
            if mv2.ok:
                log("已开启 IP 转发（重启后依然有效）")
            else:
                result.warnings.append(
                    "IP 转发没配置成功，客户端可能上不了网：" + mv2.err.strip()
                )
        else:
            result.warnings.append("写 sysctl 配置失败，IP 转发未开启")

    # 7) NAT：firewalld 场景交给 firewalld 管（Red Hat 要求别和 iptables 混用）
    if options.enable_nat and plan.nat_method == "firewalld":
        nat = target.run(
            _root_chain("firewall-cmd --permanent --add-masquerade && firewall-cmd --reload"),
            root=True,
            timeout=90,
        )
        if nat.ok:
            log("已在 firewalld 开启 masquerade")
        else:
            result.warnings.append(
                "firewalld 开启 masquerade 失败，客户端可能上不了网："
                + (nat.err.strip() or nat.out.strip())[-300:]
            )
    elif options.enable_nat and not plan.nat_method:
        result.warnings.append(
            "本机没有 iptables 命令、firewalld 也没在运行，NAT 未配置："
            "客户端能连上服务器，但访问不了互联网。"
        )

    # 8) 启动服务
    start = target.run(
        _root_chain(
            f"systemctl enable wg-quick@{_q(plan.iface)} && "
            f"systemctl restart wg-quick@{_q(plan.iface)}"
        ),
        root=True,
        timeout=90,
    )
    if not start.ok:
        detail = (start.err.strip() or start.out.strip())[-1200:]
        result.message = (
            f"配置已写入，但服务启动失败：\n{detail}\n\n"
            f"排查命令：systemctl status wg-quick@{plan.iface} --no-pager -l"
        )
        raise RuntimeError(result.message)

    verify = target.run(f"wg show {_q(plan.iface)} public-key", root=True, timeout=20)
    if (verify.out or "").strip() != public_key:
        result.warnings.append("服务已启动，但回读的公钥与预期不一致，请手工核对配置。")
    result.started = True
    log(f"wg-quick@{plan.iface} 已启动")

    # 9) 可选：放行防火墙
    if options.open_firewall and plan.firewall:
        if plan.firewall == "ufw":
            fw = target.run(f"ufw allow {plan.listen_port}/udp", root=True, timeout=30)
        else:
            fw = target.run(
                _root_chain(
                    f"firewall-cmd --permanent --add-port={plan.listen_port}/udp && "
                    "firewall-cmd --reload"
                ),
                root=True,
                timeout=60,
            )
        if fw.ok:
            log(f"已在 {plan.firewall} 放行 UDP {plan.listen_port}")
        else:
            result.warnings.append(
                f"{plan.firewall} 放行端口失败：{fw.err.strip()}，请手工放行 UDP {plan.listen_port}"
            )
    elif plan.firewall and not options.open_firewall:
        result.warnings.append(
            f"检测到 {plan.firewall} 处于启用状态，UDP {plan.listen_port} 未放行，"
            "客户端可能连不上。需要的话可手动放行。"
        )

    if options.enable_nat and plan.nat_method == "iptables" and not plan.default_iface:
        result.warnings.append(
            "未识别默认出口网卡，NAT 规则没有写入，客户端只能访问服务器本身。"
        )

    result.message = "安装完成，WireGuard 服务端已启动"
    return result
