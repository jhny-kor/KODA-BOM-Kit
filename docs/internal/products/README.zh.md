# 产品证据采集器

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 的 `Collect(context.Context, root string, paths []string)` 接收经过预检的普通文件相对路径列表。它不会发现文件、执行已安装程序、解压归档、连接服务器或读取环境与配置中的秘密。`os.OpenRoot` 限制路径解析，绝对路径及含父目录跳转的输入会被拒绝。文件内容和归档元数据的读取均有上限。路径列表为空时不进行文件发现。

## 认可的静态证据

- JDK/JRE `release` 文件中允许的版本、运行时、构建、厂商和架构字段。
- Tomcat `catalina.jar` 中 `ServerInfo.properties` 与 `MANIFEST` 的版本交叉核对。
- WebLogic `weblogic.jar` 产品清单与当前安装目录 `inventory/ContentsXML/comps.xml` 的组件身份。补丁 ID 仅作为观测值保留。通用 XML 或 `.patch_storage` 条目无法证明 CPU/PSU 补丁已应用，`patchState` 保持 `unknown`。
- 已安装产品模块下的 JBoss EAP/WildFly 产品发布清单。
- 包含产品专属内嵌版本签名的 OpenSSH、OpenSSL、PHP、Node.js ELF 文件。该分类补充 Syft，尚未证明能识别所有 stripped 或自定义二进制。原生扫描输入上限为 32 MiB，超大候选项会明确标记为不完整。

Tomcat、JDK 或同一安装目录下的 WebLogic 元数据相互矛盾时，标记冲突且不声明确定版本。不同安装目录不会合并。原生库、客户端、服务器产物保持独立 ID，即使同目录同版本也如此。不生成 CPE 推断或 CVE 判定。

JEUS 产品和补丁元数据 **不受支持**。独立的通用 Java 编目器可能采集 JAR 库，但这些库无法证明已识别 JEUS 产品或已应用的补丁级别。

测试构造代表性元数据结构，不使用授权产品镜像。商业安装验证需要目标厂商 fixture。
