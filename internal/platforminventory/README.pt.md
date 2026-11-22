# Observações nativas da plataforma

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

O `Collect(ctx)` do KODA BOM Kit coleta observações limitadas usando ferramentas já instaladas no destino. Usa argumentos fixos, prazo de 60 segundos por comando e limite de saída de 32 MiB. Seleciona os campos antes de gravá-los no SBOM. Números de série, UUIDs, nomes de usuário e caminhos completos de aplicativos são omitidos. Os caminhos locais só participam do hash de identidade do componente.

No macOS, `/usr/sbin/system_profiler` fornece metadados de hardware, software e aplicativos. O coletor emite firmware do sistema, carregador do SO, CPU e aplicativos, preservando o build do SO na string da versão. Alguns aplicativos podem não fornecer versão ou metadados.

No Windows, o PowerShell do sistema executa sem perfis e lê registros CIM computer, BIOS, OS e QuickFixEngineering, além das entradas de desinstalação do registro da máquina e do usuário atual. O build e a arquitetura do SO são preservados. QuickFixEngineering cobre apenas as atualizações que relata. O inventário do registro não enumera todos os perfis de usuário, aplicativos Store ou dependências incorporadas. O coletor registra uma ocorrência de cobertura para essas limitações.

Execute a verificação nativa do macOS com `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory`. Fixtures de análise do Windows e compilação cruzada verificam a estrutura do código. A execução real exige um destino Windows.
