#!/usr/bin/env python3
"""Update the offline language switchers in each edition, or check them in CI."""
import argparse
import os
import re
import shutil
from html import escape
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://github.com/jhny-kor/KODA-BOM-Kit'
LANGUAGES = {
    'en': ('English', 57), 'ja': ('日本語', 52),
    'zh': ('简体中文', 65), 'zh-hant': ('繁體中文', 65),
    'ko': ('한국어', 52), 'es': ('Español', 63), 'fr': ('Français', 65),
    'vi': ('Tiếng Việt', 78), 'pt': ('Português', 76), 'th': ('ไทย', 40),
    'tr': ('Türkçe', 57),
}
FAMILIES = (
    'README', 'THIRD_PARTY_NOTICES',
    'docs/air-gapped', 'docs/collector-guide', 'docs/asset-inventory',
    'docs/additional-bom', 'docs/support-matrix', 'docs/verification',
    'docs/verification-results', 'internal/assetimport/README',
    'internal/platforminventory/README', 'internal/products/README',
    'tests/oracle-vm/README', 'tests/ubuntu-vm/README',
)
BADGES = Path('docs/badges')
START = '<!-- koda-doc-nav -->'
END = '<!-- /koda-doc-nav -->'


def edition(family, lang):
    # Preserve links to the original Korean test report.
    if family == 'docs/verification-results' and lang == 'ko':
        return Path('docs/검증결과.ko.md')
    suffix = '' if lang == 'en' else '.' + lang
    return Path(f'{family}{suffix}.md')


def relative(source, dest):
    return quote(os.path.relpath(dest, source.parent), safe='/.-')


def badge_svg(label, width, color):
    label = escape(label)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="24" '
        f'viewBox="0 0 {width} 24" role="img" aria-label="{label}">\n'
        f'  <title>{label}</title>\n'
        f'  <rect width="{width}" height="24" rx="4" fill="{color}"/>\n'
        f'  <text x="50%" y="16" text-anchor="middle" font-family="system-ui, sans-serif" '
        f'font-size="12" font-weight="600" fill="white">{label}</text>\n'
        '</svg>\n'
    )


def navigation(family, current, version):
    source = edition(family, current)

    def link(target, image, label):
        src = relative(source, BADGES / (image + '.svg'))
        return f'  <a href="{target}"><img src="{src}" alt="{escape(label)}"></a>'

    items = [START, '<p align="center">']
    for lang, (label, _) in LANGUAGES.items():
        if lang == current:
            items.append(f'  <strong>{label}</strong>')
        else:
            items.append(link(relative(source, edition(family, lang)), lang, label))
    items += ['</p>', '<p align="center">',
              link(f'{REPOSITORY}/releases/tag/v{version}', 'release', f'v{version}'),
              link(relative(source, Path('LICENSE')), 'license', 'Apache-2.0')]
    if family == 'README':
        matrix = relative(source, edition('docs/support-matrix', current))
        items.append(link(matrix, 'linux', 'Linux amd64'))
    items += ['</p>', END]
    return '\n'.join(items)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='report outdated or missing files without writing')
    parser.add_argument('--stage', type=Path, metavar='DIR',
                        help='verify and copy the documentation into a release staging directory')
    args = parser.parse_args()
    version = re.search(r'^var version = "([^"]+)"', (ROOT / 'cmd/koda-bom/main.go').read_text(),
                        flags=re.MULTILINE).group(1)
    errors = []
    files = []

    def update(path, contents):
        files.append(path)
        full = ROOT / path
        if full.exists() and full.read_text() == contents:
            return
        if args.check or args.stage:
            errors.append(str(path))
        else:
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(contents)

    for lang, (label, width) in LANGUAGES.items():
        update(BADGES / f'{lang}.svg', badge_svg(label, width, '#294666'))
    for name, label, width, color in [('release', f'v{version}', 63, '#166247'),
                                       ('license', 'Apache-2.0', 88, '#654a86'),
                                       ('linux', 'Linux amd64', 95, '#405575')]:
        update(BADGES / f'{name}.svg', badge_svg(label, width, color))
    for family in FAMILIES:
        for lang in LANGUAGES:
            path = edition(family, lang)
            full = ROOT / path
            if not full.is_file():
                errors.append(f'{path} (missing translation)')
                continue
            body = full.read_text()
            if body.count(START) != 1 or body.count(END) > 1:
                errors.append(f'{path} (expected one language switcher)')
                continue
            start = body.index(START)
            end = body.index(END) + len(END) if END in body else start + len(START)
            update(path, body[:start] + navigation(family, lang, version) + body[end:])
    if errors:
        raise SystemExit('\n'.join(errors))
    if args.stage:
        files.extend([Path('LICENSE'), Path('NOTICE'), Path('tests/oracle-vm/kernels.json'),
                      Path('docs/폐쇄망_실행_결과확인_안내.ko.txt')])
        for path in files:
            dest = args.stage / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, dest)
    print(f'{len(FAMILIES)} documents × {len(LANGUAGES)} languages, v{version}')


if __name__ == '__main__':
    main()
