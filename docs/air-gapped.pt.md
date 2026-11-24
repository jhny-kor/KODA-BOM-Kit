# Execução offline e inspeção

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.9 fornece um arquivo Linux x86_64 (amd64), kernel 3.2 ou posterior. Transfira o arquivo e seu `.tar.gz.sha256` da publicação oficial. O servidor não precisa instalar Go, Python, Docker ou jq. NOTICE identifica jhny-kor e o repositório oficial.

[Publicação 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## Verificar e extrair

Coloque exatamente um arquivo correspondente e seu checksum em diretório local executável. Verifique o arquivo antes da extração e os arquivos internos depois. Checksums validam os bytes transferidos. Use a publicação oficial confiável. Copie de USB noexec para um sistema de arquivos executável.

```bash
set -- koda-bom-linux-amd64-0.1.9-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.9 archive.' >&2
fi
```

## Inspecionar o servidor

Confira arquitetura, kernel e `doctor`. `supported=true` indica requisitos de execução atendidos. `doctor.kernel` e `context.json.runningKernel` identificam o kernel observado. `kernelFlavor=unknown/unconfirmed` pode coexistir com uma versão registrada. root amplia a visibilidade de DMI, BMC, processos e contêineres.

```bash
uname -m
uname -r
./koda-bom doctor
```

## Escolher o escopo

Sem argumentos, `koda-bom` cria um diretório em `bom-output/` com `bom.cdx.json` mesclado e sete documentos em `boms/`. AI-BOM chama-se `aibom.cdx.json`. O conteúdo depende da evidência local. Para Qwen, indique o diretório real do modelo. H100 aparece no HBOM. Configuração, cabeçalhos e pacotes não determinam a alocação GPU atual nem a configuração efetiva do serviço.

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

Coleta de diretórios usa `--no-context`. Grave a saída fora da entrada. O auxiliar recusa `/` e aceita exclusões relativas para uma única pasta. Vários alvos não podem sobrepor-se e exigem exclusões absolutas. Compartilham limites de tempo/arquivos. Dependências externas podem não ser observadas.

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Coletar livepatch

O auxiliar opcional consulta clientes Ksplice, Uptrack ou Canonical existentes, limpa evidências e executa scan. Preserva evidências junto ao resultado. Capture `$?` imediatamente. Permanecem limites de 30 s por consulta e 10 s para kernel efetivo, mesmo removendo o limite scan. Clientes e daemons têm comportamento de rede próprio.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## Limites e códigos de saída

Padrões de 1,000,000 arquivos regulares e 30 minutos. `--max-files 0 --timeout 0` remove ambos e Ctrl+C cancela. Permissões, exclusões, links, 2 GiB por arquivo e limites de extração continuam. `--no-containers` omite contêineres e imagens sem uso. `--no-images` omite contêineres parados e imagens sem uso. 0 é completo, 3 parcial com resultados e 2 falha. Investigue outras saídas anormais.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## Localizar e verificar resultados

Use o diretório exato impresso. O auxiliar mostra doctor/evidências antes da última linha com o caminho. Defina `result` com esse caminho. Arquivos de root podem exigir sudo. Verifique o manifesto principal e os de cada contêiner/imagem. Preserve motivos de coleta parcial.

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

## Interpretar estados e patches

`collection.json` contém `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues`, identidade, procedência, integridade e contêineres. O contador corresponde aos arquivos selecionados no percurso. `file_limit_exceeded` fornece `limit` e `observed`. `context.json` contém kernel, processos, sockets, serviços, configurações e patches. `assets.json` contém hardware, firmware e certificados.

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` vem do kernel, `reported-applied` do cliente. `disabled` e `transitioning` preservam o estado. `stale`, `identity_mismatch` e `unknown` exigem evidência adicional. Leia estado atual e `patches[].state`, pois `reportedState` pode ser antigo. Captura com mais de 24 horas, outro boot/kernel ou futuro excessivo não comprova aplicação atual. Last-Check/CheckState da Canonical também são verificados. Interprete ausência e `not-reported-patched` com evidências de kernel/fornecedor.

`integrity.findings[].state=modified` ou `missing` indica divergência ou ausência. `bindScope=all-interfaces` descreve endereços vinculados. Exposição por firewall precisa de outra evidência. `unidentifiedExecutables` indica falta de associação a pacote. `reboot.recommended=not_observed` indica ausência de sinal. Analise contexto e limites conjuntamente.

## Comparar fornecedor e preservar

O SBOM fornecedor WAR/EAR deve conter o SHA-256 real. Hash ausente ou diferente retorna 2. Confira `reconcile.json` e motivos parciais. Preserve todo o diretório pai com evidências livepatch limpas e calcule o checksum do arquivo exportado.

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## Enviar e analisar

Envie `sbom.cdx.json` ou `sbom.spdx.json` ao Tracker compatível. Cada contêiner/imagem possui SBOM próprio. Preserve collection, context e Syft como evidências anexas. O timeout de upload é independente. A coleta alimenta análises posteriores. Eficácia dos patches e correção CVE exigem evidência própria. Consulte o histórico para o escopo exato de versões e VM.

## Documentação

[Execução offline e inspeção](air-gapped.pt.md) · [Compilação e verificação](verification.pt.md) · [Resultados de verificação](verification-results.pt.md)
