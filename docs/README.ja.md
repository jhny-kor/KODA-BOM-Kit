<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="../README.md"><img src="badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="README.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
  <a href="support-matrix.ja.md"><img src="badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>閉域網の Linux ホストから、単一の実行ファイルでソフトウェア、ハードウェア、稼働状況の証跡を収集します。KODA BOM Kit は 7 種類の CycloneDX BOM、統合 BOM、SPDX 形式のソフトウェア一覧を出力します。</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>v0.1.8 をダウンロード</b></a> ·
  原作者 <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">公式リポジトリ</a>
</p>

## クイックスタート

Linux amd64 用のアーカイブと対応する SHA-256 ファイルをダウンロードし、対象サーバーの空のディレクトリに移して次のコマンドを実行します。対象サーバーに Go や脆弱性データベースを導入する必要はなく、パッケージのダウンロードも不要です。

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## 出力ファイル

最後の行に、`bom-output/` 配下に作成したディレクトリが表示されます。統合版は `bom.cdx.json`、7 種類の個別 BOM は `boms/` にあります。

| ファイル | 記録内容 |
|---|---|
| `boms/sbom.cdx.json` | インストール済みのパッケージ、ライブラリ、アプリケーション |
| `boms/hbom.cdx.json` | デバイス、ファームウェア、ドライバー |
| `boms/cbom.cdx.json` | 証明書やアルゴリズムなどの暗号資産 |
| `boms/obom.cdx.json` | サービス、プロセス、ソケット、パッケージ間で観測した関係 |
| `boms/aibom.cdx.json` | ローカルのモデルファイル、重み、提供されたメタデータ |
| `boms/saasbom.cdx.json` | OpenAPI 文書またはサービス定義に記載されたサービスと、プロキシ設定で宣言されたバックエンド |
| `boms/mbom.cdx.json` | 提供された証跡に基づく製造・ビルド工程 |

ホストで証跡が見つからなかった BOM の項目は空になる場合があります。各 BOM の証跡ステータスと `collection.json` で理由を確認してください。Tracker には最上位の `sbom.cdx.json` または `sbom.spdx.json` を登録します。 既定の形式は CycloneDX 1.6 と SPDX 2.3 です。`--cyclonedx-17` を追加すると CycloneDX 1.7 も同時に出力します。

再統合するには、マニフェスト、関係、チェックサムを含む `boms/` ディレクトリ全体をコピーします。`run_dir` には収集の最後に表示されたパスを設定してください。

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## ドキュメント

- [閉域網への持ち込みと結果の確認](air-gapped.ja.md)
- [収集コマンドと出力ファイル](collector-guide.ja.md)
- [ハードウェア・暗号・稼働状況の証跡](asset-inventory.ja.md)
- [サービス・AI モデル・製造工程の定義](additional-bom.ja.md)
- [対応範囲と収集の制約](support-matrix.ja.md)
- [ビルドと検証の手順](verification.ja.md)
- [試験結果と検証範囲](verification-results.ja.md)

### ソースと検証環境

- [外部資産の取り込み](internal/assetimport/README.ja.md)
- [プラットフォーム別の収集](internal/platforminventory/README.ja.md)
- [製品の識別](internal/products/README.ja.md)
- [Oracle Linux VM](tests/oracle-vm/README.ja.md)
- [Ubuntu VM](tests/ubuntu-vm/README.ja.md)

## ライセンスと著作者表示

KODA BOM Kit のライセンスは Apache-2.0 です。原作者と同梱する依存コンポーネントの表示は以下を参照してください。 [Apache-2.0](../LICENSE) · [原作者の表示](../NOTICE) · [サードパーティーの表示](THIRD_PARTY_NOTICES.ja.md)
