# Oracle Linux 8.2 カーネル直接起動検証ハーネス

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`init.go` は KODA BOM Kit の **検証用 VM の PID 1** です。`//go:build ignore` により通常の Go パッケージテストから除外します。次のように明示的にビルドします。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python、Go、Docker、QEMU はビルド PC 上の検証ツールです。閉域網の対象サーバーには `koda-bom` 実行ファイルを渡します。ハーネスと Python は配布実行ファイルの依存関係に含まれません。

## 再現手順

ランナーは ARM64 ビルドホスト上の QEMU コンテナーで TCG を使って x86_64 をエミュレートします。ゲストは 4 GiB RAM と 2 vCPU、コンテナーのメモリ上限は 6 GiB です。外部ビルド PC のプロジェクトルートで実行します。`<ID>` を `run.py` が表示する実際の ID に置き換え、以前の報告書を保持してください。

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

検証ホストには `jsonschema` が必要です。`tests/schemas` に固定した公式スキーマでオフライン検証します。準備段階のダウンロードにはネットワークが必要ですが、カーネル VM は外部接続なしで動作します。タグは変更され得るため、実行時のイメージ ID を保持します。

`prepare.py` は [kernels.json](kernels.json) に固定した 4 個の RPM（合計 120,245,036 バイト）の SHA-256 とサイズ、および Oracle Linux 8 署名鍵のフィンガープリントを検証します。新しい Oracle テストコンテナーの RPM DB に公開鍵を取り込み、`rpm -Kv` で署名を確認し、`--nodeps --noscripts --notriggers` でカーネルをインストールします。これはカーネルイメージ、モジュール、RPM メタデータ検証用のファイルシステムを作る手順です。通常のインストーラースクリプト、dracut、GRUB 設定は対象外です。

既存の作業ディレクトリで最終配布バイナリを指定して `prepare.py` を再実行し、キャッシュ済みカーネル/RPM ファイルシステムからコレクター、検証 PID 1、initramfs を再構築します。両カーネル VM を再起動し、**最終バイナリの SHA-256** を baseline と照合します。以前のビルドの VM 結果では新しいリリースを検証できません。

`input-provenance.json`、`rpm-signature-install.log`、各実行の `command.json`、`serial.log`、`boot-report.json`、`validation.json`、`results/baseline.json`、両 SBOM とチェックサムを保存します。provenance は RPM、カーネル、initramfs、PID 1、コレクターのハッシュと Oracle/QEMU イメージ ID を記録します。別の配布検証報告書で証拠と配布アーカイブの SHA-256 を結び付けます。

## ゲストの準備

検証用 initramfs には Oracle Linux 8.2 ファイルシステム、両インストール済みカーネルの RPM DB、`/boot` のカーネルイメージ、両 `/lib/modules` ツリー、検証対象 `/koda-bom`、ハーネス `/init` を含めます。RHCK と UEK は各自のカーネルイメージで直接起動する必要があります。コンテナーや QEMU user-mode のみの実行ではこの起動証拠になりません。必要に応じて公式カーネル RPM から抽出した一致するモジュールを次の場所に置きます。

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

ハーネスはモジュールの SHA-256 を記録し、`init_module` でロードを試みます。モジュール欠落、ロード済み、署名・依存関係による失敗は状態とエラーを個別に記録します。`loadedModulesAfter` とコレクターの `loadedModules` を照合してロードを確認します。未観測だけで機能がないとは判断できません。

QEMU に外部ネットワークインターフェースや仮想ディスクは接続しません。`-accel tcg,thread=single -cpu max -smp 2 -m 4096` を使用します。初期起動時の `getrandom` 待ちを避けるため、テストゲストに `random.trust_cpu=on` を指定します。本番設定の推奨ではありません。実際の CPU・アクセラレーション設定とカーネル、RPM、initramfs、コレクターのチェックサムをホスト側に保存します。

## 実行と収集

ハーネスは `/proc`、`/sys`、`/dev`、`/tmp`、`/results` をマウントし、合成ホスト名を設定します。独立 baseline に uname、`/proc/sys/kernel/osrelease`、OS release、ロード前後のモジュール一覧、VM カーネル引数、コレクターのチェックサムを記録します。ホスト名とカーネル引数はこの合成 VM 証拠だけに含め、製品の通常収集ポリシーは変更しません。コレクターを次のように 1 回実行します。

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

`--target /payload` を指定せず、既定の live-host モードを使います。0.1.3 の検証はファイル数と時間の上限を 0 にして解除します。検証 PID 1 の独立した 11 分 watchdog とホスト QEMU の期限は、資源回収のため維持します。stdout と stderr は各 1 MiB に制限し、別ファイルに保存します。終了コード、時間、エラーを `/results/baseline.json` に記録します。終了 3 は部分収集として保持します。

結果はシリアル出力の次のマーカー間に **base64(gzip(tar))** として送信されます。

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

非圧縮合計が 256 MiB または 10,000 ファイルを超えると、失敗理由を含む baseline だけを出力します。出力後は sync と poweroff を試みます。失敗時も PID 1 を維持して kernel panic を避けます。期限超過時はホストランナーが QEMU を終了させます。

## 必須の判定項目

- baseline の uname と proc release が一致し、RHCK/UEK が意図したバージョンで起動している。
- `context.json.mode=live-host` と `runningKernel` が独立 baseline に完全一致する。
- UEK は `kernelFlavor=UEK`、RHCK は現行契約の `RHCK-compatible` を報告する。
- ネイティブインベントリに両インストール済みカーネルと RPM の epoch/version/release/arch/source package が残る。
- インストール済みカーネルと context が示す実行中カーネルが区別される。
- モジュールの `metadata.kernelVersion` と `versionMagic` が各ツリーに一致し、ロード一覧がアクティブカーネルの baseline に一致する。
- 両 SBOM のスキーマとチェックサムが合格し、収集失敗・部分状態がそのまま報告される。

## 検証範囲の限界

- 実際の Oracle RHCK/UEK ゲストカーネルを起動します。物理 x86_64 サーバーの検証は別途必要です。
- Oracle Linux 8.2 ユーザー空間と公式カーネルを custom initramfs で使います。systemd 全体の起動、GRUB インストール、UEFI/Secure Boot、SELinux enforcing、本番サービス統合は対象外です。
- `loop` テストは 1 個の実モジュールのロードと観測を確認します。全ドライバーや全ハードウェアを網羅しません。非アクティブカーネルのインストール済みモジュールをロード済みと解釈しません。
- 終了 `3` と `collection.status=partial` は理由を保持して許容します。カーネル識別、標準出力、整合性の合格は全ファイルの完全収集を示しません。
