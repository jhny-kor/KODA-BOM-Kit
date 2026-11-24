# 検証結果

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification-results.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification-results.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification-results.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification-results.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification-results.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification-results.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit と旧版の検証記録です。各結果はビルドハッシュ、環境、部分収集と未検証範囲を伴います。現行版 0.1.9 のアーカイブ、チェックサム、実行範囲は公式リリースで確認します。新しいバイナリにはそのバイナリの検証が必要です。

[リリース 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 2026-11-21 — 分割と結合

`f0610ca-worktree-00ed83f2acd8` で `scan --separate-boms`、`bom-split`、`bom-merge`、`domain-bom` を 0.1.6 の保管結果 2 件に対して検証しました。全項目・関係を独立比較し、各結合にルート間関係を 1 本追加しました。Ubuntu の証明書 ID 10 組は別位置の 20 レコードとして保持し、結合後の重複 ID はゼロでした。Linux ARM64 では観測 4 種と OpenAPI・モデル・SLSA・製造の合成入力を検証し、実 TCP 18443 を Perl とパッケージに接続しました。スキーマとハッシュは合格。署名と現場証拠の真偽は別途確認します。

| 保管結果 | 項目数 元 / 結合 | 関係数 元 / 結合 |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — 運用関係

`f0610ca-worktree-06f22395e26f` は部分収集の保管結果 2 件から OBOM を再生成しました。ソケットは名前空間・プロセスごとに集計します。Debian ARM64 の `127.0.0.1:18443/tcp` を `/usr/bin/perl` と `perl-base` に接続し、Redfish 部品番号 3 件、TLS 宣言例、ビルド関係 2 件、チェックサム 11 件を確認しました。再生成 OBOM はバイト一致。合成 Kubernetes 5 リソースを保管コンテナー ID に接続しました。運用クラスタ、実機、実 TLS セッションは未検証です。

| 保管結果 | コンテナー | ソケット ホスト + コンテナー | パッケージ接続 ホスト + コンテナー | 照合関係 |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — Daybreak 12 件の修正

旧 KODA-SBOM-Maker `cc86c1b` の指摘に対応しました。Go 設定隔離、展開と同一入力のハッシュ、256 レイヤー制限とハッシュ再利用、ZIP/ZIP64 上限、whiteout 検証、排他的出力先、勧告照合の索引と上限、Python 最適化拒否、確認済みルート内読み取り、短い ID、RPM epoch 衝突判定、256 項目単位の中断可能な走査が対象です。

macOS ARM64 の Go・vet・配布ガードが合格。Go 1.26.11 / Syft 1.57.1 で静的 Linux amd64 をオフラインビルドし、306 チェックサムが合格しました。通信を切った Debian の CLI とディレクトリー試験も合格。変更前後のパッケージ 88、OS 1、装置 20、ドライバー 15 は一致し、両収集は制限を記録した partial でした。追加プラットフォームはクロスビルドを確認し、実行と新規 VM 回帰は範囲外です。

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Docker Desktop `7.0.14-linuxkit` で Linux・Go・vet が合格。CPU は lscpu と一致し、カーネル設定 1,736 件を取得。Debian は 147 中ローカル 1 件が未記録、Rocky はリポジトリー 167 件とローカル・未記録インストールを区別しました。稼働 9、停止 14、未使用イメージ 11 から 35 SBOM を約 3 分 30 秒で生成。対応するパッケージ数 796・71・51 は一致。overlay2 の書き込み層 curl と未使用 busybox を確認し、削除された一時コンテナーは `not_collected`。実 x86、systemd、Kubernetes/k3s/Podman/CRI-O、新規 VM は未検証です。

## 2026-11-19 — 0.1.6

Debian 12 / Linux ARM64 / Docker Desktop `7.0.14-linuxkit` で検査しました。ホスト識別、実ソケット、稼働 Docker 16 件と外部カーネルモジュール 5 件を確認。735 ファイル約 89 MB の整合性検査で意図的変更 1 件と移動・欠落 1 件を検出。RSA-1024・ECDSA P-384 の期限・弱い鍵を検査し、秘密鍵は出力しません。ハードウェア、snap/flatpak/conda、一部設定は fixture。実 RAID/NIC/BMC、運用 SELinux、他ランタイム、新規 VM は未検証です。

## 2026-11-18 — 0.1.6-dev

Go・vet・ヘルパー・シェル検査が合格。Linux amd64/ARM64 と実 macOS ARM64 の基本資産出力がスキーマ・ハッシュ検査に合格しました。Windows はクロスビルドのみ。削除・置換された実行ファイル、イメージハッシュ、ローカル勧告を検査しました。Tracker ローカルパーサーは両 CycloneDX を読めました。運用導入・ブラウザーは未確認。704/811 ライセンス ID と追加 107 件の意味保持を確認し、チェックサム件数は範囲で異なります。

## 0.1.2–0.1.5 の履歴

0.1.5 は pnpm と Maven POM 関係、0.1.4 はディレクトリーヘルパー、0.1.3 は時間・件数制限を追加しました。付属する `release.json`、`VERIFICATION.json`、`dist/evidence/v0.1.x/final-verification.json` をハッシュで照合します。0.1.2 は最終バイナリで Ubuntu と Oracle 2 カーネルを再検証しました。契約クライアントの導入・実パッチ適用は合成ヘルパー試験の範囲外です。

## 2026-10-29 — 実装と Oracle VM

初期実装は Linux 検査 68 件と vet に合格。uid 65534、読み取り専用、capability なし、通信なしでスキーマ・PURL・canary・失敗状態・ハッシュを確認しました。Oracle コンテナーは RPM 182、Python 5、binary 2。guest syscall は通信と追加 execve がゼロ。隔離 Tracker の両形式アップロードは HTTP 202。小規模 0.1.0 fixture は 0.78 秒、peak RSS 219,644 KiB でした。

Oracle Linux 8.2 VM の署名済み RHCK・UEK を起動し、uname/proc と loop が一致しました。両方 5,516 項目で RPM 186、カーネル 2、モジュール 5,321、Python 5、binary 2。モジュール内訳は RHCK 2,478、UEK 2,843。スキーマと各 5 ハッシュが合格。終了 3、partial、context completed でした。保護ファイル、範囲外リンク、OpenSSH 文字列衝突、Syft 警告を保持しています。

| Kernel | 収集 / 全体 秒 |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## 証拠の限界

初期 VM は下記 0.1.0 ハッシュを使用し、後続版は個別報告を持ちます。実 x86 サーバー、完全 OS・サービス統合、供給者パッチ適用は未検証です。QEMU guest trace と native ptrace は実行環境が異なります。稼働中の収集は時間差を含むため、変更の少ない時間帯か読み取り専用スナップショットを使用してください。版番号・未観測だけでは CVE 対象や対処完了を確定できません。

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## 関連文書

[閉域環境での実行と結果確認](air-gapped.ja.md) · [ビルドと検証](verification.ja.md) · [検証結果](verification-results.ja.md)
