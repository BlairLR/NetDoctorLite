# NetDoctor Lite

面向 Windows 10（1809 及以上）和 Windows 11 的 x64 网络诊断工具。它只读检查，不修改网络设置，也不会结束进程或关闭端口。

## 安装与使用

1. 双击 `dist\NetDoctorLite.exe`。这是便携版，无需安装 Python，也不需要管理员权限。
2. 点击 **开始检测**。网站列表独立显示 DNS、TCP 443、HTTPS、HTTP 状态码、响应耗时和异常原因。自定义网址可只填域名，默认使用 HTTPS；如网址指定了其它端口，HTTPS 会使用该端口，而独立 TCP 检测仍使用 443。
3. 如需测试代理，勾选 **测试指定代理**，填写本机代理软件显示的协议、主机和端口，可选填认证信息。默认主机为 `127.0.0.1`，端口为 `7890`；请以实际配置为准。凭据在启动一轮检测后会从输入框清空。HTTP 认证使用 Basic，SOCKS5 使用代理端 DNS。
4. 使用 **复制诊断结果** 或 **导出 TXT** 分享脱敏报告。报告保留端口、PID 和进程名称，隐藏代理配置值、非回环的具体监听地址、自定义网址及公网出口 IP。公网出口 IP 只显示在结果界面。

## 如何解读结果

- **端口监听** 来自本机 TCP 表，仅说明有进程在等待连接。Windows 系统代理、PAC、自动检测以及当前进程、当前用户和系统环境变量只显示配置状态；工具不运行 PAC 脚本，也不采用这些设置发送请求。
- **代理协议握手** 使用标准库 HTTP CONNECT 或 PySocks，检查指定代理是否接受到测试站点的隧道。目标隧道被拒绝也可能是代理策略或上游问题，不能单凭此项判断代理未启动。
- **代理访问外网** 通过显式指定的代理请求 Cloudflare 的 HTTPS 测试端点，要求证书验证通过且返回 2xx。直连显式忽略环境代理。应用层直连仍经过操作系统既有路由；透明代理或 TUN 可能让两条通路的出口相同。
- **公网出口 IP** 优先从 Cloudflare 的响应读取，必要时查询 api.ipify.org。IP 查询失败不影响已成功的通路结果；两条通路出口相同不代表没有使用指定代理。
- 网站检测不跟随重定向。HTTPS 成功表示收到了经过 TLS 验证的 HTTP 响应；403、429、5xx 等响应仍可能意味着网站功能不可用。外网探测是当时对指定目标的抽样。

## 从源码运行和构建

在项目目录用 Windows x64 的 Python 3.12 打开 PowerShell：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\build.ps1 -Python .\.venv\Scripts\python.exe
```

`requirements.txt` 是运行依赖，`requirements-build.txt` 增加 PyInstaller；`requirements-lock.txt` 固定了本次交付使用的版本。构建产物为 `dist\NetDoctorLite.exe`。打包后可运行下面的冒烟检查，它会创建实际 Qt 窗口、触发一轮检测并验证结果和报告入口：

```powershell
(Start-Process .\dist\NetDoctorLite.exe -ArgumentList '--smoke-test' -PassThru -Wait).ExitCode
```

退出码 0 表示界面和诊断流程完成。该检查不要求外网目标可达。自动测试中的监听和协议握手用本机临时端口，不需要修改已有代理设置。
