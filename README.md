# NetDoctor Lite

面向 Windows 10（1809 及以上）和 Windows 11 的 x64 网络诊断工具。它只读检查，不修改网络设置，也不会结束进程或关闭端口。

## 安装与使用

1. 双击 `dist\NetDoctorLite-v1.1.0-windows-x64-portable.exe`。这是便携版，无需安装 Python，也不需要管理员权限。
2. 点击 **开始检测**。网站列表并排显示直连 HTTPS 和代理 HTTPS 的状态码、耗时或失败原因。悬停可看详情。DNS 和 TCP 443 两列属于直连测试。自定义网址可只填域名，默认使用 HTTPS。如指定其它端口，HTTPS 会使用该端口，独立 TCP 检测仍使用 443。
3. 勾选 **对比直连与代理**。默认的 **自动检测本机代理** 会在每轮测试中检查 Windows 手动代理指向的本机端口、常用端口和已识别代理进程的端口，再用 HTTP 和 SOCKS5 验证 Cloudflare HTTPS。找到可用代理后，各网站及自定义网址会使用该代理，结论里会显示选中的协议和端口。
4. 下拉栏也可以直接选常用本机端口，或手动填写 HTTP / SOCKS5、主机、端口和认证信息。自动检测适用于无需认证的本机代理。仅提供 VPN 隧道的软件，可以分别在连接和断开时运行直连测试。凭据会在启动检测时从输入框清空。
5. 使用 **复制诊断结果** 或 **导出 TXT** 分享脱敏报告。报告保留端口、PID 和进程名称，隐藏代理配置值、非回环的具体监听地址、自定义网址及公网出口 IP。公网出口 IP 只显示在结果界面。

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

`requirements.txt` 是运行依赖，`requirements-build.txt` 增加 PyInstaller；`requirements-lock.txt` 固定了本次交付使用的版本。构建产物为 `dist\NetDoctorLite-v1.1.0-windows-x64-portable.exe`。打包后可运行下面的冒烟检查，它会创建实际 Qt 窗口、触发一轮检测并验证结果和报告入口：

```powershell
(Start-Process .\dist\NetDoctorLite-v1.1.0-windows-x64-portable.exe -ArgumentList '--smoke-test' -PassThru -Wait).ExitCode
```

退出码 0 表示界面和诊断流程完成。该检查不要求外网目标可达。自动测试中的监听和协议握手用本机临时端口，不需要修改已有代理设置。

## 发布文件管理

当前版本为 v1.1.0，版本源文件为 `netdoctor/version.py`。每次发布更新该文件和 `CHANGELOG.md` 后运行构建脚本。窗口、报告、Windows 文件属性和产物名称使用同一个版本号。

`dist` 目录并列保存以下文件。

- `NetDoctorLite-v1.1.0-windows-x64-portable.exe`
- `NetDoctorLite-v1.1.0-source.zip`
- `NetDoctorLite-v1.1.0-SHA256SUMS.txt`

版本号采用主版本、次版本、修订版本的形式。兼容性功能新增递增次版本，兼容性修复递增修订版本。正式发布后，版本号对应的内容保持固定，后续修改使用新版本号。

历史正式版保留版本化名称。开发期间生成的无版本文件收纳到 `dist/archive/development`，便于查找当前正式发布文件。GitHub Release 使用对应的 `v版本号` 标签，并上传同版本的文件。

Windows PowerShell 可以通过 `Get-FileHash -Algorithm SHA256 文件路径` 与校验清单核对文件。
