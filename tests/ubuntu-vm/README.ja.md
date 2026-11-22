# Ubuntu 24.04.1 実カーネル VM 検証

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

これは KODA BOM Kit のテストツールです。閉域網サーバーに配布する実行ファイルの依存関係ではありません。Ubuntu Base **24.04.1 amd64** と公式 Ubuntu カーネル **6.8.0-47-generic / パッケージ 6.8.0-47.47** を custom initramfs で直接起動します。QEMU user-mode やディレクトリ fixture では実カーネル起動の証拠になりません。

Ubuntu Base の原本は保存済み Ubuntu 配布ミラーから取得します。SHA256SUMS.gpg を Ubuntu CD Image Automatic Signing Key (2012) `843938DF228D22F7B3742BC0D94AA3F0EFE21092` で検証します。認証された rootfs 内の Ubuntu archive keyring で、公式 Snapshot サービスの 2024-10-18 noble-updates InRelease を検証します。署名済み Release → Packages.xz → 2 個の DEB の SHA-256 とサイズを連結して検証します。入力 URL、チェックサム、署名ログ、Docker イメージ ID をすべて保持します。

ビルドホストには Go、Python 3 と `jsonschema`、Docker、GnuPG（`gpg`/`gpgv`）が必要です。Oracle VM のツールイメージを再利用します。対象サーバーへのこれらのツールのインストールは不要です。プロジェクトルートで次を実行し、`<ID>` は実際の実行 ID に置き換えます。

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` は Oracle ハーネスの上限付きエクスポートと独立 baseline の設計を再利用します。Ubuntu の loop ドライバーは組み込みのため、実際の `dummy.ko` をロードしてモジュール観測を検証します。実行中の uname と proc release、OS、コレクター SHA、ロード済みモジュールを独立記録し、両 SBOM を固定済み公式スキーマ、チェックサム、DEB 原本のバージョン/source/PURL、インストール済みカーネル/モジュールと照合します。新しい最終バイナリを渡すたびに prepare、run、validate を再実行します。

テスト rootfs は `dpkg --unpack` で原本 DEB を展開し、実際の dpkg DB を作ります。依存関係の強制許容後も unpack 状態に残し、通常の apt インストールや設定完了を示すものではありません。systemd 全体の起動、GRUB、UEFI/Secure Boot、本番サービス、物理ハードウェアは別途検証します。QEMU に NIC/ディスクを接続せず、Docker は `--network none`、読み取り専用 rootfs、capability 削除で動作します。実際の商用・サブスクリプション live patch の導入は対象外です。

0.1.3 の検証は `--max-files 0 --timeout 0` でコレクターの両制限を解除します。テスト PID 1 の独立した 11 分 watchdog とホスト QEMU ランナーの期限は維持します。

provenance、署名ログ、dpkg ログ、`command.json`、`serial.log`、`boot-report.json`、`baseline.json`、両 SBOM、`validation.json` をまとめて保存します。部分収集の終了 3 を完全収集の終了 0 に変換しません。
