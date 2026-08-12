# UniFi Policy Manager 双认证版 4.1.5

[![Build](https://github.com/daidaiya7/unifi-policy-manager/actions/workflows/build.yml/badge.svg)](https://github.com/daidaiya7/unifi-policy-manager/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/daidaiya7/unifi-policy-manager)](https://github.com/daidaiya7/unifi-policy-manager/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

UniFi Network 双认证策略管理工具。Windows 与 macOS 均支持 API Key 和 UniFi OS 本地管理员用户名密码两种登录方式：API Key 通过 Ubiquiti Integration API 提供完整管理；本地账号建立 Cookie 会话，在兼容的 Network 版本上支持 DNS 读取与写入，ACL 和防火墙保持只读。

> **重要：本地账号 DNS 写入取决于 Network 版本。** 软件通过 `/proxy/network/v2/api/site/{site}/static-dns` 尝试 DNS 新增、编辑、启停、删除和批量操作。若控制器返回 403、404 或 405，软件会立即将 DNS 降级为只读并提示改用 API Key。ACL、防火墙、策略排序和策略变更中心的正式执行仍仅 API Key 可用。

- Windows：C# / .NET 8 / WPF 完整版
- macOS：SwiftUI 原生完整版，与 Windows 版共享官方 API 功能范围和安全写入流程
- 双认证：API Key 完整管理；或 UniFi OS 本地管理员用户名密码进行分级管理（兼容版本可写 DNS，ACL/防火墙只读；不支持云端 SSO、2FA、Passkey）
- Cookie 接口取决于 Network 版本；某个读取接口不可用时会明确标注，并提示改用 API Key，不会影响其他可用部分

## 4.x 主要变化

- 4.1.5：本地账号 Cookie 模式增加 DNS 单项与批量写入；不支持该 v2 写端点的 Network 版本会自动降级为只读
- 4.1.4 双认证版：同步上游 Windows/macOS 完整功能；两端均支持 API Key 和本地账号登录，Cookie 模式按 Network 版本提供只读访问
- 4.1.4：修复 macOS 内置规则区域滚动，并延续统一发布与签名流程
- 4.1.3：强化 Windows/macOS 发布签名、打包和校验流程
- 4.1.2：macOS 补齐策略变更中心、DNS 批量导入/删除、212 条内置规则和策略排序
- 4.1.1：将 212 条转发域规则真正编译进 EXE，点击“载入内置规则（212）”即可直接使用
- 4.1.0：发布包内置 212 条按服务分类的转发域 CSV，选择文件后即可预览、去重并批量新增
- 4.0.2：改用单元格模板强制策略变更、DNS、ACL、防火墙表格的正文、复选框和操作按钮垂直居中

- 全新侧边栏工作台：概览、策略变更中心、DNS、ACL、防火墙独立页面
- 新增完整策略基线导入、导出和差异计算
- 一份计划统一管理 DNS、ACL 与防火墙的新增、更新和删除
- 导出的基线包含 ACL 与防火墙用户策略排序
- 执行前自动保存完整快照，可直接载入上次执行前快照生成恢复计划
- 严格同步默认关闭；删除项必须主动开启并手动选择
- 无效或重复项目会自动阻止对应策略范围生成删除项
- 兼容旧版 DNS-only 备份，不会误删 ACL 或防火墙策略

## 支持范围

API Key 模式通过官方 Integration API 支持的 Policy Table 类型：

- ACL 规则：列表、新增、编辑、启停、删除、排序
- DNS 记录：转发域名、A、AAAA、CNAME、MX、TXT、SRV 的完整 CRUD
- 防火墙策略：列表、新增、编辑、启停、删除、排序

官方公开 API 当前没有 NAT、基于策略的路由、端口转发、QoS、静态路由接口，因此 4.0 不提供这些类型，也不会使用 SSH。

### 认证能力矩阵

| 功能 | API Key | 本地账号 Cookie |
| --- | --- | --- |
| 登录与多站点选择 | 支持 | 支持 |
| DNS、ACL、防火墙读取 | 支持 | 支持；取决于 Network 版本提供的本地接口 |
| DNS 单项及批量写入 | 支持 | **兼容版本支持；403/404/405 时自动降级只读** |
| ACL/防火墙新增、编辑、启停、删除 | 支持 | **不支持，仅 API Key** |
| 策略排序、策略变更中心正式执行 | 支持 | **不支持，仅 API Key** |
| 导出当前已读取基线 | 支持 | 支持 |

## 直接使用

### Windows

双击：

```text
UniFi-Policy-Manager.exe
```

### macOS

macOS 14 或更高版本可从源码构建原生 SwiftUI 应用：

```bash
./macos/build-app.sh
open macos/dist/UniFi-Policy-Manager.app
```

macOS 端使用系统钥匙串保存 API Key 或本地账号密码；API Key 模式写入前会将完整实时基线保存到
`~/Library/Application Support/UniFiPolicyManager/backups`。macOS 已包含策略变更中心、
212 条内置规则、TXT/CSV/XLSX 批量导入、批量删除和策略排序。完整说明见 [`macos/README.md`](macos/README.md)。

连接时填写：

- UCG 地址，例如 `192.168.1.1`
- 选择 API Key，并填写在 `unifi.ui.com → Settings → API Keys` 创建的密钥；或选择本地账号，填写 UniFi OS 本地管理员用户名和密码
- UCG 使用自签名证书时不要勾选“验证 HTTPS 证书”
- Windows 勾选“记住认证凭据”后，密钥或密码使用 DPAPI 按当前用户加密保存；macOS 使用系统钥匙串

本地账号登录调用 UniFi OS 的 `/api/auth/login` 建立 Cookie 会话，然后从 Network 本地会话接口智能分项读取站点、DNS、ACL 和防火墙数据；它不会再尝试用 Cookie 访问只接受 `X-API-Key` 的 `/proxy/network/integration/v1/...`。DNS 通过 v2 `static-dns` 接口尝试 CRUD 和批量写入，写入前重新读取并保存 DNS 实时快照；如果该版本不允许 Cookie 写入，软件会自动禁用后续 DNS 写操作。ACL 和防火墙仍为只读。仅支持 UniFi OS 本地管理员账号，不支持 Ubiquiti 云端 SSO、2FA 或 Passkey 账号。

## 策略变更中心

1. 点击“导出当前基线”，保存当前 DNS、ACL、防火墙和排序。
2. 修改或选择另一个基线 JSON，然后点击“载入 JSON”。
3. 程序计算新增、更新、删除、不变和无效项目。
4. 默认只选择新增与更新；开启“严格同步”后才会生成删除项，并恢复用户策略排序。
5. 检查并手动选择需要执行的项目，再点击“执行所选变更”。

写入通过官方端点逐条完成。执行前保存的快照位于：

```text
%LOCALAPPDATA%\UniFiPolicyManager\backups
```

执行一次变更计划后，可以点击“载入上次快照”生成恢复计划。恢复仍需预览和确认，不会绕过安全检查。

跨站点导入会按策略 ID 或名称匹配；网络和防火墙区域 UUID 必须在目标站点有效。

## ACL 与防火墙编辑

ACL 和防火墙使用完整 JSON 请求体编辑器，以覆盖官方 Schema 的组合字段：

- 新增策略提供官方字段模板，默认 `enabled: false`
- 编辑时自动移除 `id`、`index`、`metadata` 等只读字段
- 保存前检查必填字段、动作类型、IP 版本及引用 UUID
- 编辑器显示 Networks、Firewall Zones 等参考 UUID
- 系统定义和派生策略只读；只有 `USER_DEFINED` 策略允许修改和删除

## DNS 批量功能

批量新增支持官方 DNS API 的全部 7 种记录：

- 转发域名（`NS` 或 `FORWARD_DOMAIN`）、A、AAAA、CNAME、MX、TXT、SRV
- 导入 TXT、CSV、XLSX；旧式“一行一个域名”清单仍按转发域名导入
- 内置 Excel 兼容 CSV 模板，包含 TTL、优先级、权重、端口、服务、协议和启用状态
- 自动规范化、验证、去重并跳过已存在记录
- 批量删除目前仍只限转发域名

EXE 内部直接封装了 212 条按服务分类的转发域规则，不依赖外部 CSV 文件。内置规则的 DNS 服务器留空，使用时：

1. 在“转发域默认 DNS 服务器”中填写自己的 DNS 服务地址；如果已有转发域，程序会尝试自动填充。
2. 点击“载入内置规则（212）”。
3. 检查导入统计，然后点击“预览并新增”。
4. 程序会跳过已存在规则，并在正式新增前显示完整预览。“选择外部规则文件”仍可导入自定义 TXT、CSV 或 XLSX。

## 安全

- Windows 使用 DPAPI 当前用户加密 API Key 或本地账号密码；macOS 使用系统钥匙串，设置文件中不保存明文密钥或密码
- API Key、用户名和密码不写入策略基线、快照或操作日志
- 修改前自动备份；操作日志位于 `%LOCALAPPDATA%\UniFiPolicyManager\logs\operations.ndjson`
- 系统/派生策略保持只读
- 不使用 SSH；API Key 模式只访问公开 Integration API，本地账号模式只访问 Cookie 会话可用的 Network 本地读取接口

## 一键打包与发布

仓库的 GitHub Actions 分工如下：

- `Windows CI` 与 `macOS CI` 只负责提交和 Pull Request 的自动编译检查。
- 手动发布时只运行 `Package & Release`，不要分别运行两套 CI。

操作步骤：

1. 打开 GitHub 仓库的 `Actions` → `Package & Release` → `Run workflow`。
2. 输入不带 `v` 的版本号，例如 `4.2.0`；创建 Release 时不能与已有 Tag/Release 重复。
3. 根据需要选择是否标记为预发布；如果只想下载 Actions Artifacts、不创建 Release，可关闭“创建 GitHub Release”。
4. 工作流会并行构建 Windows 与 macOS；Windows 还会运行完整自测。
5. 两端全部成功后，自动创建 `v版本号` 的 GitHub Release，并同时上传：
   - `UniFi-Policy-Manager-版本号-win-x64.zip`
   - `UniFi-Policy-Manager-版本号-macOS.zip`
   - `SHA256SUMS.txt`

任一平台构建或自测失败时不会创建 Release。

发布工作流默认不要求购买代码签名证书：Windows 会生成未签名 EXE，macOS 会生成启用 Hardened Runtime 的 ad-hoc 签名应用。配置证书后，工作流会自动执行 Windows Authenticode、macOS Developer ID 签名和 Apple 公证。具体配置和免费/付费选择见 [`SIGNING.md`](SIGNING.md)。

## 演示与自测

```powershell
.\publish-4.1.5\UniFi-Policy-Manager.exe --demo
```

```powershell
Start-Process .\publish-4.1.5\UniFi-Policy-Manager.exe -ArgumentList '--self-test','--self-test-output=self-test.json' -Wait
```

## 构建

开发环境：Windows 10/11 与 .NET 8 SDK。

```powershell
.\build.ps1
```

输出：

```text
publish-4.1.5\UniFi-Policy-Manager.exe
UniFi-Policy-Manager-4.1.5-win-x64.zip
```

也可以直接使用标准 .NET 命令：

```powershell
dotnet restore .\UniFiDnsManager.csproj
dotnet build .\UniFiDnsManager.csproj -c Release --no-restore
```

仓库内置 GitHub Actions 工作流。每次推送或 Pull Request 都会在 Windows 环境构建项目，并生成自包含的 `win-x64` EXE 构建产物。

## 仓库安全

- 不要提交真实 API Key、连接设置、策略快照、操作日志或包含私人网络信息的截图
- `.gitignore` 默认排除本地 SDK、构建目录、发布包、日志、备份和环境文件
- 提交前建议运行 `git status`，确认暂存区只包含源码和文档
