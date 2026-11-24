# Coletor de evidências de produtos

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

O `Collect(context.Context, root string, paths []string)` do KODA BOM Kit recebe uma lista previamente verificada de arquivos comuns com caminhos relativos. Não descobre arquivos, executa programas instalados, extrai arquivos compactados, contata servidores nem lê segredos de ambiente ou configuração. `os.OpenRoot` limita a resolução dos caminhos. Caminhos absolutos ou com travessia para diretórios pais são rejeitados. A leitura de conteúdo e metadados de arquivos é limitada. Uma lista vazia não inicia descoberta de arquivos.

## Evidências estáticas aceitas

- Campos permitidos de versão, runtime, build, fornecedor e arquitetura de arquivos JDK/JRE `release`.
- Conferência de versões entre `ServerInfo.properties` e `MANIFEST` no `catalina.jar` do Tomcat.
- Manifesto de produto WebLogic `weblogic.jar` e identidade do componente em `inventory/ContentsXML/comps.xml` da instalação atual. IDs de patches são preservados como observações. XML genérico ou entradas de `.patch_storage` não comprovam a aplicação de um patch CPU/PSU. `patchState` permanece `unknown`.
- Manifestos de versão JBoss EAP/WildFly no módulo do produto instalado.
- Arquivos ELF OpenSSH, OpenSSL, PHP e Node.js com assinaturas de versão embutidas específicas do produto. Essa classificação complementa o Syft. A cobertura de todos os binários stripped ou personalizados não foi estabelecida. A entrada nativa é limitada a 32 MiB, e candidatos maiores são explicitamente incompletos.

Metadados contraditórios de Tomcat, JDK ou WebLogic na mesma instalação são marcados em conflito sem afirmar uma versão. Instalações diferentes nunca são mescladas. Bibliotecas, clientes e servidores nativos mantêm IDs separados, mesmo com a mesma versão no mesmo diretório. Não são geradas inferências CPE nem avaliações CVE.

Metadados de produto e patches JEUS **não são suportados**. O catalogador Java genérico pode coletar bibliotecas JAR, que não comprovam a identidade do produto JEUS nem o nível de patch aplicado.

Os testes constroem estruturas representativas de metadados sem imagens de produtos licenciados. A validação de instalações comerciais exige fixtures do fornecedor de destino.
