# 製品証拠コレクター

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
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

KODA BOM Kit の `Collect(context.Context, root string, paths []string)` は、事前確認済みの通常ファイルの相対パス一覧を受け取ります。ファイル探索、インストール済みプログラムの実行、アーカイブ展開、サーバー接続、環境や設定の秘密情報の読み取りは行いません。`os.OpenRoot` でパス解決を制限し、絶対パスや親ディレクトリへの移動要素を拒否します。ファイル内容とアーカイブメタデータの読み取りには上限があります。空のパス一覧では探索を行いません。

## 認定する静的証拠

- JDK/JRE `release` ファイルの許可されたバージョン、ランタイム、ビルド、ベンダー、アーキテクチャのフィールド。
- Tomcat `catalina.jar` の `ServerInfo.properties` と `MANIFEST` のバージョン照合。
- WebLogic `weblogic.jar` の製品マニフェストと、現在のインストールホームにある `inventory/ContentsXML/comps.xml` のコンポーネント識別情報。パッチ ID は観測値として保持します。汎用 XML や `.patch_storage` 項目では CPU/PSU パッチの適用を証明できず、`patchState` は `unknown` のままです。
- インストール済み製品モジュール配下の JBoss EAP/WildFly 製品リリースマニフェスト。
- 製品固有の埋め込みバージョンシグネチャがある OpenSSH、OpenSSL、PHP、Node.js の ELF ファイル。この分類は Syft を補完し、すべての stripped バイナリや独自ビルドを識別できる保証はありません。ネイティブスキャン入力の上限は 32 MiB で、超過する候補は不完全と明示します。

Tomcat、JDK、同じホームの WebLogic メタデータが矛盾すると、競合と記録しバージョンを断定しません。異なるインストールホームは結合しません。ネイティブライブラリ、クライアント、サーバーの成果物は、同じディレクトリで同じバージョンでも別の ID を維持します。CPE の推論や CVE 判定は生成しません。

JEUS の製品・パッチメタデータは **未対応** です。別の汎用 Java カタロガーが JAR ライブラリを収集することはありますが、JEUS 製品の識別や適用済みパッチレベルの証明にはなりません。

テストでは代表的なメタデータ構造を生成し、ライセンス製品のイメージは使用しません。商用インストールの検証には対象ベンダーの fixture が必要です。
