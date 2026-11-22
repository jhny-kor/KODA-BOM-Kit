# ネイティブなプラットフォーム観測

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit の `Collect(ctx)` は対象にインストール済みのツールで範囲を制限した観測を行います。引数は固定し、コマンドごとに 60 秒の期限と 32 MiB の出力上限を設けます。SBOM に出力する前にフィールドを選択します。シリアル番号、UUID、ユーザー名、アプリケーションの完全なパスは除外します。ローカルパスはハッシュ化されたコンポーネント識別子にのみ使用します。

macOS では `/usr/sbin/system_profiler` からハードウェア、ソフトウェア、アプリケーションのメタデータを取得します。システムファームウェア、OS ローダー、CPU、アプリケーションを出力し、OS バージョン文字列に OS ビルドを保持します。一部のアプリケーションではバージョンやメタデータが取得できない場合があります。

Windows ではプロファイルを読み込まずにシステム PowerShell を実行し、CIM の computer、BIOS、OS、QuickFixEngineering レコード、およびコンピューター全体と現在のユーザーのアンインストールレジストリ項目を読み取ります。OS ビルドとアーキテクチャを保持します。QuickFixEngineering が対象とする更新は自身が報告するものに限られます。レジストリから全ユーザープロファイル、Store アプリ、組み込み依存関係を列挙することはできません。これらの制限は対象範囲の問題として記録します。

ネイティブ macOS の検証は `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory` で実行します。Windows の解析 fixture とクロスコンパイルはソースの構造を検証します。Windows での実行検証には Windows 環境が必要です。
