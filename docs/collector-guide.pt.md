# KODA BOM Kit — Comandos de coleta e arquivos de saída

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## Escolher o escopo

No host em execução, o coletor inventaria o sistema operacional, os pacotes, os contêineres e o hardware acessível. Uma varredura de diretório cobre sua árvore. A de imagem lê um arquivo Docker ou OCI exportado. Escolha um tipo de entrada por execução. Os limites padrão são um milhão de arquivos regulares e 30 minutos. Com `--max-files 0 --timeout 0` esses limites são removidos. As permissões e os limites de sistema de arquivos e de análise de arquivos compactados continuam em vigor.

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## Examinar um ou mais diretórios

O script recebe o diretório de destino e, opcionalmente, o diretório pai dos resultados. Ele usa `--no-context` e recusa `/`. Coloque caminhos com espaços entre aspas. Use `--exclude-dir` para um diretório e `--exclude` para um padrão. Com vários alvos, escolha árvores sem sobreposição e caminhos absolutos para excluir diretórios. As localizações conservam `target-1`, `target-2` após a consolidação.

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## Ler o estado de correções a quente

A varredura do host lê o estado do kernel em sysfs. O script opcional consulta clientes Canonical Livepatch, Ksplice ou Uptrack instalados e filtra a saída. Para valer como atual, um relatório importado deve coincidir com a inicialização e o kernel e ter no máximo 24 horas. A ausência de uma entrada não permite concluir se um CVE foi corrigido.

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## Recriar o grafo operacional ou consolidar listas

O OBOM do host relaciona sockets em escuta, processos e pacotes instalados. O endereço local de escuta sozinho não comprova acesso externo. Adicione observações exportadas com `--kubernetes-evidence` ou `--network-evidence`. Defina `set_dir` como o diretório com `bom-set.json` criado na separação. Guarde os arquivos de relações e as somas de verificação. Conjuntos antigos com `mlbom.cdx.json` também podem ser consolidados.

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## Fornecer evidências para outras listas

Indique ao coletor de IA o diretório do modelo instalado. Para SaaS ou fabricação, forneça um manifesto de serviços ou processos. Use `--asset-evidence` para dispositivos Redfish, firmware ou observações criptográficas. A lista de compilação é vinculada ao artefato examinado quando seu SHA-256 coincide. Os guias ao final da página descrevem os formatos de entrada.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## Importar registros de IBM AIX e Oracle

Execute o script no AIX e o importador no host Linux de análise. Forneça a saída do OPatch salva pelo proprietário do Oracle Home e, se necessário, o histórico de patches SQL exportado pelo DBA. Até oito Homes distintos são aceitos. A versão do Listener exige evidências do mesmo Home. Confira os IDs de patches no aviso aplicável do fornecedor.

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## Identificar dependências implantadas

Para npm e pnpm, as relações dependem dos locais de instalação, da resolução dos pares e das versões. A detecção de JavaScript estático cobre jQuery, jQuery UI e Fancytree. Go usa dados de compilação embutidos e Rust ELF, dados cargo-auditable. Para .NET, confronte .deps.json com as DLLs gerenciadas implantadas. Ruby usa gemspecs instaladas. Java preserva caminhos em WAR, EAR e Spring Boot aninhados. Coordenadas desconhecidas ficam sem resolução.

## Comparar a implantação com a lista do fornecedor

Forneça um WAR ou EAR e um documento CycloneDX 1.4–1.7 ou SPDX 2.3 com o SHA-256 exato do arquivo. Consulte `common`, `observedOnly`, `supplierOnly` e `unresolved` em `reconcile.json`. Envie ao Tracker a lista observada. O limite é de 512 MiB para a implantação e 32 MiB para a lista do fornecedor.

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## Conferir a cobertura

Em uma máquina de compilação ou testes, compare a mesma implantação imutável com KODA, Syft e Trivy. O script precisa de Python 3.11 ou posterior. Use `--expected` para componentes e relações verificados ou `--baseline` para detectar regressões. Os testes opcionais de Tracker enviam dados ao serviço de testes indicado. Para examinar o grafo armazenado, forneça `--normalized-bom-command`.

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## Interpretar os resultados

Defina `run_dir` como o caminho exibido pelo coletor. Os códigos de saída são 0 para coleta completa, 3 para parcial e 2 para falha. Veja limites, omissões e erros em `collection.json`, relações em execução em `context.json` e evidências de dispositivos ou certificados em `assets.json`. Cada contêiner ou imagem tem suas próprias somas de verificação. A versão e a data não bastam para determinar a presença de uma vulnerabilidade.

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## Compilar em outra máquina

A máquina de compilação usa Go e Python 3. Esta versão foi compilada com Go 1.26.11. Para outro executável Go, forneça o caminho e o SHA-256 verificado. Uma compilação offline requer um cache de módulos preenchido. O arquivo distribuído é para Linux amd64 e o código também compila para Linux ARM64. A procedência da compilação fica em `release.json`.

```sh
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## Documentação

- [Instalação offline e verificação de resultados](air-gapped.pt.md)
- [Evidências de hardware, criptografia e operação](asset-inventory.pt.md)
- [Manifestos de serviços, modelos de IA e fabricação](additional-bom.pt.md)
- [Plataformas compatíveis e limites de coleta](support-matrix.pt.md)
- [Procedimentos de compilação e verificação](verification.pt.md)
- [Resultados e escopo dos testes](verification-results.pt.md)
