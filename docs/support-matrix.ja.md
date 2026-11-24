# 収集範囲と証拠の限界

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


識別できる証拠を示します。各回の状態と理由を `collection.json` で確認してください。収集範囲は読めるメタデータ、インストール形式、権限に依存します。脆弱性評価には勧告との照合が必要です。

## CycloneDXの7種のBOM

通常のホスト `/` 収集では `boms/` に個別文書、`bom.cdx.json` に統合版を作ります。`--cyclonedx-17` で1.7版を追加します。証拠不在は `no-evidence` と不明範囲で明示します。[CycloneDX分類](https://github.com/CycloneDX/specification#readme)

| BOM | 取得できる証拠 | 追加資料 |
|---|---|---|
| SBOM | OS・言語パッケージ、版/PURL、ライセンス・依存関係、JAR、内蔵モジュール、コンテナー | 成果物SHA-256と対応する供給者/CI CycloneDX・SPDXで静的/ビルド依存を補完し `build-sbom.cdx.json` に出力 |
| HBOM | CPU・基板・機器・ドライバー・ファームウェア、EDAC DIMM、電源・ファン、SMBIOSのメモリーモジュール（製造元・部品番号・速度）・電源ユニット・スロット | 見えない部品、部品番号、供給者、ライフサイクルのRedfish・資産台帳 |
| CBOM | 公開証明書・鍵・アルゴリズム、検証した発行関係、TLS/SSH設定、JKS、SSHホスト公開鍵、システム暗号ポリシー、OpenSSLのプロトコル・暗号スイート・グループ宣言 | TLS実測とHSM/KMS/保護ストアの公開メタデータ |
| OBOM | ホスト・コンテナー・プロセス・実行ファイル・パッケージ・ソケット、systemd、プロセスごとの外部TCP接続先、systemdタイマー、cronジョブ、ファイアウォール設定の宣言 | 同一クラスターのPod/workload/Service/Ingress JSON、配置ラベル、ホスト一致の `--network-evidence` |
| SaaSBOM | サービス仕様/OpenAPIを `saasbom.cdx.json` に変換。OpenAPI YAMLと、nginx・Apache・HAProxy設定で宣言されたバックエンドも対象 | 提供者・カタログ・API、外部依存、認証、信頼境界、分類したデータフロー |
| AI-BOM | 設定、量子化/コンテキスト、重みインデックス、GGUF/safetensorsヘッダー/サイズ、Ollama。明示成果物の全体SHA-256。`aibom.cdx.json`。ONNXヘッダー、PyTorch pickleのimport安全性、Hugging Faceのモデルカード・キャッシュref、モデルサーバーが起動時に指定したモデルも観測 | モデルID・リビジョン・重み・系譜、カード/ライセンス、学習/評価データ出所 |
| MBOM | 一致したSLSAまたは物理組立/試験の宣言・報告を `mbom.cdx.json` の `formulation` へ | CI工程・ツール・入出力・実行記録、製造工程・検査履歴 |

## 層ごとの収集

| 層 | 証拠と制約 |
|---|---|
| OS | os-release/vendor releaseとRPM/DEB/APK DB。権限・破損・source package/module stream欠落で制限されます |
| 機器・ファームウェア | CPU/マイクロコード/CPUID/トポロジー/ARM、DMI、BIOS/UEFI/ESRT、PCI、NVMe/SCSI、USB、TPM。RAID/HBA・RDMA・GPU VBIOS・NIC ioctlはドライバー依存。megaraid_sasはエクスポート、BMCはroot/IPMIと版照合が必要。VM/コンテナーで物理ホストを示す場合があります |
| 外部資産 | 展開済みRedfish、fwupd、devlink、共通JSON。報告された版・状態を保持し未対応機器を確認します |
| Windows/macOS | システム・OS・ファームウェア・アプリ。Windowsはクロスビルド確認を含みます。アプリ内部依存・メーカー更新は追加証拠が必要です |
| 実行ソフトウェア | 同じファイルシステム範囲で実行/共有ライブラリと所有パッケージを対応。置換は再起動レビューの根拠です |
| ホスト識別 | ホスト `/` のmachine-id/DMI UUID/シリアルSHA-256と資産タグ。権限・共通初期値を考慮。仮名化情報です |
| 待受ソケット | 同じ名前空間のTCP LISTEN/UDPとプロセスFD。バインドのみでは到達性不明。所有者不明は `unattributedSockets` |
| 外部接続 | ローカルポートが待受ポートでないESTABLISHED TCPを、プロセスと接続先ごとに集計（最大16,384ソケット）。固定ローカルポートから相手の一時ポートへの接続は受け付けた接続として扱います。収集時に開いている接続のみ、ホストのプロセスのみが対象。このホストが待ち受けるポートへの接続は、その待受ソケットと所有プロセスに結びます |
| 定期ジョブ | `/etc/crontab`、`/etc/cron.d`、ユーザーcrontab、`cron.{hourly,daily,weekly,monthly}` のスクリプト、有効なsystemdタイマーの `On*` スケジュール。実行ファイルの絶対パスのみ記録し、引数は破棄 |
| ファイアウォール | iptables-saveファイル（RHEL・Debian・ufw）、firewalldの既定ゾーンとサービス定義、nftablesのinput hookチェーンとリテラルinclude。ファイル上の宣言で、カーネルに読み込まれたルールは読みません。ポリシーのないbase chainは許可、`ENABLED=no` のufwは `disabled`、systemdユニットがインストール済みで有効化も実行もされていない、またはマスクされたフレームワークは `not-enabled` とし、どちらも有効とみなしません。ループバック専用・確立済み状態・否定のルールは開いたポートとみなさず、プロトコル全体のTCP/UDP許可はそのプロトコルの全ポートを開くとみなします。ホストのネットワーク名前空間にあるループバック以外の待受ソケットに `firewall-declared`（`accept-declared`、`accept-declared-restricted`、`policy-accept-declared`、`no-accept-declared`、`undetermined`、有効な宣言を読めなかった場合は `none-observed`）を付与。コンテナのソケットは独自のネットワーク名前空間にあるため付与しません。コンテナがNATで公開するポートはFORWARDルールを通るため評価しません |
| 設定・再起動 | SELinux、AppArmor、lockdown、FIPS、許可起動引数、カーネル `y`/`m`、再起動要求、実行モジュール、新しい同系統カーネル。信号不在だけでは再起動不要を証明できません |
| SSH | グローバル宣言。`Match` を除外し `Include` の実効優先順位は計算しません |
| taint・モジュール | `kernel.tainted`、`/proc/modules`、sysfsのversion/srcversion |
| 不明実行ファイル | 同じrootでパッケージ・構成要素・製品に帰属しない実行中ファイル。他mount namespaceを除外。追加調査で分類します |
| パッケージ出所 | apt平文/gz/lz4、dnf履歴、yumdb。aptは名前照合。削除履歴・dnf5・apkは非対応。URL/パスは省略 |
| 起動サービス | systemd wants/requires、unit/drop-in、cgroup v1/v2。最初のExecStart、相対実行パスはパッケージ未接続。独自sliceは停止表示の場合あり。SysVは非対応。有効なタイマーは `On*` スケジュールと起動するサービスを記録 |
| 機器CPE | Intel Xeon/Core、AMD EPYC/Ryzen、Dell PowerEdge機器/BIOS、Lenovo ThinkSystem機器。辞書/モデル欠落で一致しない場合あり。HPE/BMCは省略 |
| 整合性 | RPM/dpkg/apkの実行/ライブラリハッシュ。設定/ghost除外、ホスト8 GiB・コンテナー1 GiB。prelinkによる誤差の可能性 |
| CBOM・証明書 | PEM/DER、公開鍵/アルゴリズム、JKS v1/v2公開チェーン・別名ハッシュ。暗号化鍵を読み飛ばし整合性未検証。主体/発行者名、秘密鍵、PKCS#12内容、OS信頼ストア、20証明書超の束は除外。SSHホスト公開鍵も記録。`crypto-policies` と `openssl.cnf` のMinProtocol/CipherString/Ciphersuites/Groupsは宣言として記録し、`.include` とセクションの有効化は解決しません |
| カーネル | uname、インストール済みイメージ/モジュール、vermagic、RPM版。実行中とインストール済みを区別。モジュール欠落は内蔵機能の可能性があります |
| ライブパッチ | livepatch sysfs、Oracle raw Ksplice、任意Ksplice/Uptrack/Canonical helper。起動・カーネル・時刻不一致は適用根拠に使いません。CVEは別解析が必要です |
| Java | JDK/JRE release、JAR/WAR/EAR manifest、Maven。shaded metadataの削除/変更で部分識別 |
| PHP | パッケージ/インタープリター、インストール済みComposer/PEAR。lockのみの未インストール項目は除外。悪用条件は設定依存 |
| snap/flatpak/conda | snap currentと内包DEB、flatpak active/AppStream、conda-meta。snap/flatpakはgeneric PURL、AppStreamなしは版不明、condaはチャネル名のみ |
| Python | dist-info/egg-info、venv、`.pyz`/`.pex` 実データ。削除/読取不可で制限 |
| Node.js・静的JS | node_modules/runtime、ファイルとEAR/WAR/ZIP/JAR内jQuery/jQuery UI/Fancytree。ファイル名だけでは確定せず対応構造/検査上限に依存 |
| Go/Rust | Go build infoとcargo-auditable ELF。情報なしは依存不明、破損/過大は部分収集 |
| .NET | `.deps.json`、管理DLLと単独DLLの版。単独DLLにNuGet PURLは付けず、single-fileは追加検証 |
| Ruby | インストール済みspecification/gemとdefault gem。Gemfile.lockだけやメタデータ欠落は不十分 |
| ネイティブサーバー | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB。独自・strip・静的複製は不明の場合あり |
| Javaサーバー | Tomcat ServerInfo/manifest/catalina.jar、WebLogic/JBoss/WildFly製品・パッチ情報。`.patch_storage` 単独では有効パッチを証明しません。実fixtureのないJEUS等は未検証 |
| 停止コンテナー/イメージ | Docker overlay2、containerd overlayfs/k3s/RKE2、rootful Podman/CRI-O。16 GiB/rootと空き容量で一時再構築を制限。他ドライバー/rootlessは非対応。待受ソケットなし |
| 稼働コンテナー | procfs rootとディスク状態、`containers/<name>/` ごとのSBOM。volume/bind mountとKubernetes sandboxを除外。不可視rootは理由記録。APIへ接続せず当該プロセスのソケットのみ帰属 |
| アーカイブ | 明示したLinux amd64 Docker/OCI tar、ハッシュ、検証済みmanifest digest。対象はイメージ内、ホストカーネル/実行状態は別観測 |
| AIX/Oracle | `aix-import` のfileset、暫定修正、HomeごとのOPatchと任意SQL履歴。1台最大8 Home。稼働状態は別証拠 |

手動インストールはディレクトリ/インスタンスを保持します。同じ名前・版でも配置先やパッチ状態は異なり得ます。不明なCPEは空にし、確定した識別子と証拠で後続レビューを行います。

既定はCycloneDX 1.6・SPDX 2.3、追加でCycloneDX 1.7です。[資産インベントリと評価](asset-inventory.ja.md) に `assess` とOSV/CSAF・証拠形式、[追加BOM証拠](additional-bom.ja.md) にサービス・モデル・製造を説明しています。

## 回帰検証のシナリオ

PHPとComposer、Node runtimeとnode_modules、JDKの完全ビルド、WebLogic配置/パッチ、手動TomcatとAJP/HTTP2、httpd/mod_http2のdistro版、nginx出所/alias/rewrite、OpenSSL CLI/libssl/libcryptoの別コピー、実行中/インストール済みUEK/RHCKを検証します。これらは識別証拠を試すシナリオで、脆弱性結論には勧告照合が必要です。
