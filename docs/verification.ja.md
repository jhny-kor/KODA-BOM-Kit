# ビルドと検証

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.9 は Linux amd64 用のオフライン配布アーカイブと SHA-256 を提供します。実行ファイルのハッシュと試験環境で検証対象を特定してください。Linux ホスト収集は x86_64 と ARM64、Docker/OCI アーカイブは linux/amd64 が対象です。macOS・Windows の基本資産収集は OS の固定読み取り専用コマンドを使用します。Windows での実行は未検証です。過去の VM 結果は記録されたビルドに対応します。

[リリース 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 出力形式と整合性

標準出力は CycloneDX 1.6 と SPDX 2.3 です。`--cyclonedx-17` は同じインベントリから 1.7 も生成します。`--format cyclonedx` との組み合わせは CycloneDX 2 文書、`--format spdx` との組み合わせは出力前に拒否されます。対象は `scan`、`aix-import`、`asset-import`、`platform-inventory`、`reconcile` と収集ヘルパーです。期待するファイルを実際のオプションと照合します。

| 出力 | 形式 |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` はローカルスキーマ、識別情報、証拠、属性、ライセンスの意味、関係、範囲、チェックサムの欠落・重複・ハッシュを検査します。1.7 スキーマは公式 1.7.1 のコミット `b29bae660048e0ad2fbc5f2972927b442ce951c4` に固定され、来歴は `tests/schemas/provenance.json` にあります。ライセンス ID は 1.6 が 704、1.7 が 811。追加 107 件は 1.6 の `license.name` と 1.7 の `license.id` で保持します。スキーマ合格後も `collection.json` の部分収集を確認します。

## ビルド端末での確認

Go、Python、Docker、Go モジュールのキャッシュとスキーマ依存関係を準備します。`trusted_go_sha256` に検証済み Go 実行ファイルのハッシュを設定し、`GOPROXY=off` でキャッシュを使用します。配布 QA は `python3 -O` と `PYTHONOPTIMIZE` を拒否します。対象サーバーは配布実行ファイルを使用します。macOS のチェックサム確認は `shasum -a 256 -c SHA256SUMS` です。

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## 統合試験の範囲

展開した最終配布物に対して次のコマンドを実行します。ネットワークを切る前に依存資料を準備します。.NET/Ruby は .NET 10 SDK、Go/Rust はキャッシュと固定済み ripgrep ELF または `--rust-binary` を使います。Fancytree は npm SHA-512 または GitHub SHA-256 を照合します。対応する試験に `--tracker-root /path/to/tracker` を指定するとローカル Tracker パーサーも検査します。

`domain_bom_integration.py` は対象バイナリを直接起動するため Linux amd64 で実行します。

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/runtime_smoke_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

試験は Java の入れ子、pyz/pex、Go/Rust、パッケージ出所、範囲、供給者のハッシュ、PURL と関係を確認します。Linux fixture はソケット、コンテナー、ファームウェア、サービス、設定、整合性、証明書を対象にします。AIX fixture は Oracle Home、Listener、OPatch を確認します。物理 BMC/NIC/OT、実際の Kubernetes ストレージ、契約済みパッチクライアントには現場の証拠が必要です。 GitHub Actions（`.github/workflows/ci.yml`）は `main` へのプッシュとプルリクエストごとに、書式、全ビルド対象の vet、Go テスト、リリースガード、バイナリ検査、上流キャッシュを要しない上記コンテナ試験を実行します。文書だけの変更は `docs.yml` が確認します。リリースビルド、キャッシュを使う上流試験、VM 検証は引き続きビルド端末で実行します。

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/scripts)

## Linux カーネルと VM 再現

Linux 専用試験は Linux で実行します。macOS からクロスビルドした試験は同じアーキテクチャのコンテナーで動かせます。VM には最終配布バイナリを使用します。Oracle RHCK `4.18.0-193.el8.x86_64` と UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` を別々に起動します。署名済み RPM は `tests/oracle-vm/kernels.json` で固定しています。来歴、署名、イメージ ID、シリアルログ、基準値と検証結果を保存します。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

Oracle runner は QEMU system TCG、メモリー 4 GiB、CPU 2 個、専用 PID 1 を使用し、ゲストのネットワークとディスクを持ちません。uname、proc、loop モジュール、インストール済みと稼働中のカーネルを検査します。Ubuntu は認証した資料から `6.8.0-47-generic` を起動します。GRUB、UEFI/Secure Boot、systemd 全体、SELinux enforcing、実機ドライバー、運用サービスは別途検証します。Oracle コンテナーはホストカーネルを共有します。

[Oracle VM](tests/oracle-vm/README.ja.md) · [Ubuntu VM](tests/ubuntu-vm/README.ja.md)

## システムコール、資源制限、後続分析

隔離環境で最終バイナリを追跡します。ARM64 エミュレーションで ptrace レジスターを解釈できない場合、`trace-network.sh` は 77 を返します。QEMU guest syscall を使う場合は実行環境を記録します。試行ゼロの主張には正常な追跡が必要です。任意の livepatch ヘルパーが呼ぶ供給者クライアント・daemon の通信は別の検証範囲です。

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

既定は通常ファイル 1,000,000 個、30 分です。各制限、無効オプション、中断、権限、破損、除外を検査します。`--max-files 0 --timeout 0` はこの制限を解除します。実入力の経過時間と peak RSS を記録します。並列度 2 はメモリー上限ではありません。Tracker は一時 DB で両標準形式を確認します。ローカル勧告の評価は入力規則と観測に依存し、運用導入と CVE 対処は独自の証拠が必要です。

## 関連文書

[閉域環境での実行と結果確認](air-gapped.ja.md) · [ビルドと検証](verification.ja.md) · [検証結果](verification-results.ja.md)
