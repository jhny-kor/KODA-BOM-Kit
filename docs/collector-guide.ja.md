# KODA BOM Kit — 収集コマンドと出力ファイル

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## 対象を選ぶ

実行中のホストでは OS、パッケージ、コンテナと読み取り可能なハードウェアを収集します。ディレクトリを指定するとその配下を、イメージを指定するとエクスポート済みの Docker／OCI アーカイブを調べます。1 回の実行で選べる入力形式は 1 種類です。既定の上限は通常ファイル 100 万件と 30 分です。`--max-files 0 --timeout 0` でこの 2 つを解除しても、アクセス権やアーカイブ解析の上限は残ります。

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## 複数のディレクトリを調べる

シェルスクリプトには対象と、任意で出力先の親ディレクトリを渡します。`--no-context` で実行し、対象に `/` は指定できません。空白のあるパスは引用符で囲みます。`--exclude-dir` はディレクトリ、`--exclude` はパターンを除外します。複数の対象は範囲が重ならないようにし、除外ディレクトリは絶対パスで指定します。統合後も `target-1`、`target-2` と検出位置が残ります。

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## ライブパッチの状態を読む

ホスト収集は sysfs のカーネル状態を読みます。任意のスクリプトはインストール済みの Canonical Livepatch、Ksplice、Uptrack に問い合わせ、出力を整形します。現在の証跡として扱うには、ブートとカーネルが一致し、取得から 24 時間以内である必要があります。記録がない場合、個別の CVE が修正されたかどうかは判断できません。

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## 運用グラフの再生成と再統合

OBOM は待ち受けソケット、プロセス、インストール済みパッケージを関連付けます。バインド先だけでは外部からの到達性は分かりません。エクスポートした観測を `--kubernetes-evidence` や `--network-evidence` で追加できます。`set_dir` には分割で作成した `bom-set.json` のディレクトリを指定し、関係ファイルとチェックサムも一緒に保管します。旧名 `mlbom.cdx.json` のセットも再統合できます。

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## ほかの BOM に証跡を与える

AI モデルの配置ディレクトリを指定します。SaaS や製造工程にはサービス定義や工程のマニフェストを渡します。`--asset-evidence` は Redfish デバイス、ファームウェア、暗号資産の証跡を取り込みます。ビルド SBOM と実物の対応は SHA-256 の一致で確認します。入力形式は末尾のガイドに掲載しています。

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## IBM AIX と Oracle の記録を取り込む

スクリプトを AIX 上で実行し、Linux の解析ホストで取り込みます。Oracle Home の所有者が保存した OPatch 出力と、必要に応じ DBA の SQL パッチ履歴を指定します。異なる Home を最大 8 件扱えます。Listener のバージョン判定には同じ Home の証拠を使い、パッチ ID は該当するベンダーの告知と照合します。

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## 配備済みの依存関係を調べる

npm と pnpm は配置場所、peer の解決先、バージョンを照合します。静的 JavaScript は jQuery、jQuery UI、Fancytree が対象です。Go は埋め込みビルド情報、Rust ELF は cargo-auditable、.NET は .deps.json と配備済みのマネージド DLL、Ruby はインストール済み gemspec を使用します。Java は WAR、EAR、Spring Boot の入れ子アーカイブ内の位置を保持します。座標が不明な項目は未確定のままです。

## 配備物と供給元の SBOM を比較する

WAR または EAR と、そのアーカイブ自体の SHA-256 を含む CycloneDX 1.4–1.7 または SPDX 2.3 文書を指定します。`reconcile.json` の `common`、`observedOnly`、`supplierOnly`、`unresolved` を確認し、Tracker には観測した SBOM を登録します。上限は配備物 512 MiB、供給元の SBOM 32 MiB です。

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## 収集範囲を検証する

ビルドまたは QA ホストで変更のない同一の配備物を KODA、Syft、Trivy で比較します。比較スクリプトには Python 3.11 以降が必要です。確認済みの構成要素と依存関係には `--expected`、回帰検査には `--baseline` を使います。任意の Tracker 検証では指定したテストサービスにアップロードします。保存後のグラフは `--normalized-bom-command` で照合できます。

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## 結果を読む

`run_dir` に収集結果のパスを設定します。終了コードは 0 が完了、3 が部分収集、2 が失敗です。上限・欠落・エラーは `collection.json`、稼働時の関係は `context.json`、機器や証明書の証跡は `assets.json` を確認します。各コンテナとイメージにも個別のチェックサムがあります。バージョンと日付だけでは脆弱性は判定できません。

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## 別のマシンでビルドする

ビルドホストには Go と Python 3 が必要です。このリリースでは Go 1.26.11 を使いました。別の Go を使う場合は検証済み実行ファイルと SHA-256 を指定します。オフラインビルドには取得済みモジュールのキャッシュが必要です。配布アーカイブは Linux amd64 用で、ソースからは Linux ARM64 にもビルドできます。来歴は `release.json` に保存されます。

```sh
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## ドキュメント

- [閉域網への持ち込みと結果の確認](air-gapped.ja.md)
- [ハードウェア・暗号・稼働状況の証跡](asset-inventory.ja.md)
- [サービス・AI モデル・製造工程の定義](additional-bom.ja.md)
- [対応範囲と収集の制約](support-matrix.ja.md)
- [ビルドと検証の手順](verification.ja.md)
- [試験結果と検証範囲](verification-results.ja.md)
