# 閉域環境での実行と結果確認

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 は Linux x86_64 (amd64)、カーネル 3.2 以降向けです。公式リリースのアーカイブと対応する `.tar.gz.sha256` を搬入します。対象サーバーに Go・Python・Docker・jq の追加インストールは不要です。NOTICE に jhny-kor と公式リポジトリーを記載しています。

[リリース 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 検証と展開

同一版のアーカイブ 1 個とチェックサムを実行可能なローカルディレクトリーに置きます。展開前にアーカイブ、展開後に内部ファイルを確認します。チェックサムは転送時の内容を検証します。信頼した公式リリースから入手してください。noexec の USB からは実行可能なローカル領域へコピーします。

```bash
set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.8 archive.' >&2
fi
```

## ホストの確認

アーキテクチャ、稼働カーネル、`doctor` を確認します。`supported=true` は実行前提条件の合格です。`doctor.kernel` と `context.json.runningKernel` が観測版を示します。`kernelFlavor=unknown/unconfirmed` でも版情報は記録できます。root は DMI・BMC・プロセス・コンテナーの観測範囲を広げます。

```bash
uname -m
uname -r
./koda-bom doctor
```

## 収集範囲の選択

引数なしの `koda-bom` は `bom-output/` に新しい結果を作り、`bom.cdx.json` と `boms/` の 7 種を生成します。AI-BOM は `aibom.cdx.json` です。内容と完全性はローカル証拠に依存します。Qwen は実際に読めるモデルディレクトリーを指定します。H100 は HBOM に入り、設定・ヘッダー・パッケージだけでは現時点の GPU 割当と実サービング設定を確定できません。

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

ディレクトリー収集は `--no-context` を使います。出力先を対象外に置きます。ヘルパーは `/` を拒否し、単一対象の `--exclude-dir` は相対指定できます。複数対象は重複不可で、除外ディレクトリーは絶対パスです。時間・件数制限は全対象で共有します。対象外の依存ライブラリーは未観測になる場合があります。

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## ライブパッチ収集

任意のヘルパーは既存 Ksplice・Uptrack・Canonical クライアントを照会し、証拠を整形して scan を実行します。整形済み証拠は結果の隣に保存します。直後に `$?` を取得します。照会は 30 秒、実効カーネル照会は 10 秒のままで、scan の制限解除には連動しません。供給者クライアント・daemon の通信は別途確認します。

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## 制限と終了コード

既定は通常ファイル 1,000,000 個と 30 分。`--max-files 0 --timeout 0` で両方を解除し、Ctrl+C で中断できます。権限、除外、リンク、ファイルごと 2 GiB、イメージ展開制限は継続します。`--no-containers` はコンテナー・未使用イメージ、`--no-images` は停止コンテナー・未使用イメージを省略。0 は完了、3 は結果付き部分収集、2 は失敗です。その他の異常終了も調査してください。

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## 結果と整合性の確認

表示された実際の結果ディレクトリーを使います。ヘルパーは doctor と証拠の後、最後に結果パスを表示します。`result` をそのパスに設定します。root 作成ファイルには sudo が必要な場合があります。親とコンテナー・イメージ各チェックサムを検査し、部分収集の理由も保存します。

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## 収集とパッチ状態の読み方

`collection.json` は `status`、`packageCount`、`packageTypes`、`limits`、`filesystemFileCount`、`issues`、ホスト、出所、整合性、コンテナーを記録します。ファイル数は事前走査で選択した数です。`file_limit_exceeded` は `limit` と `observed` を持ちます。`context.json` は稼働カーネル、プロセス、ソケット、サービス、設定、ライブパッチ、`assets.json` は装置・ファームウェア・証明書の証拠です。

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` はカーネル直接観測、`reported-applied` はクライアント報告です。`disabled`・`transitioning` はその状態を保持します。`stale`・`identity_mismatch`・`unknown` は追加確認が必要です。過去の `reportedState` だけでなく現在の状態と `patches[].state` を読みます。24 時間超、別ブート・カーネル、許容外の未来時刻は現在の適用証拠にできません。Canonical Last-Check/CheckState も確認します。未観測や `not-reported-patched` は供給者・カーネル情報と合わせて解釈します。

`integrity.findings[].state=modified`・`missing` は内容不一致・欠落、`bindScope=all-interfaces` はバインド範囲を示します。ファイアウォールの外部公開は別証拠が必要です。`unidentifiedExecutables` はパッケージ未関連付け、`reboot.recommended=not_observed` は再起動信号未観測です。関連証拠と限界を合わせて確認します。

## 供給者との照合と保存

WAR/EAR の供給者 SBOM は実ファイル SHA-256 を持つ必要があります。欠落・不一致は終了 2。`reconcile.json` と部分収集理由を確認します。整形済みライブパッチ証拠を含む親ディレクトリーを保存し、搬出アーカイブのハッシュを計算します。

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## アップロードと後続分析

対応 Tracker には `sbom.cdx.json` または `sbom.spdx.json` を渡します。コンテナー・イメージは個別 SBOM を持ちます。collection、context、Syft は付属証拠として保存します。アップロード時間制限は別設定です。収集結果は勧告との後続分析に使用し、現パッチ効果や CVE 対処は独自の証拠で確認します。過去 VM と各版の検証範囲は検証記録を参照してください。

## 関連文書

[閉域環境での実行と結果確認](air-gapped.ja.md) · [ビルドと検証](verification.ja.md) · [検証結果](verification-results.ja.md)
