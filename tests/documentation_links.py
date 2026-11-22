#!/usr/bin/env python3
"""Check language navigation and relative links in the packaged offline docs."""
import importlib.util
import re
import subprocess
import sys
import tempfile
import unicodedata
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
NAV = ROOT / 'scripts/docs-navigation.py'


class HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        url = attrs.get({'a': 'href', 'img': 'src'}.get(tag))
        if url:
            self.links.append(url)
        if 'id' in attrs:
            self.ids.add(attrs['id'])


@lru_cache(maxsize=None)
def parse(doc):
    text = re.sub(r'^ *`{3,}[^\n]*\n.*?^ *`{3,} *$', '', doc.read_text(),
                  flags=re.MULTILINE | re.DOTALL)
    html = HTMLLinks()
    html.feed(text)
    links = html.links + re.findall(r'\]\(([^)\s]+)\)', text)
    anchors = html.ids.copy()
    for heading in re.findall(r'^#{1,6}\s+(.+)$', text, flags=re.MULTILINE):
        slug = ''.join(c for c in heading.lower() if c in '-_ ' or
                       unicodedata.category(c)[0] in 'LMN').replace(' ', '-')
        anchor = slug
        n = 0
        while anchor in anchors:
            n += 1
            anchor = f'{slug}-{n}'
        anchors.add(anchor)
    return links, anchors


def main():
    spec = importlib.util.spec_from_file_location('navigation', NAV)
    nav = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nav)
    with tempfile.TemporaryDirectory() as directory:
        stage = Path(directory)
        subprocess.run([sys.executable, NAV, '--stage', stage], check=True)
        errors = []
        count = 0
        for family in nav.FAMILIES:
            for lang in nav.LANGUAGES:
                src = stage / nav.edition(family, lang)
                links, _ = parse(src)
                siblings = {(stage / nav.edition(family, other)).resolve()
                            for other in nav.LANGUAGES if other != lang}
                for url in links:
                    parsed = urlsplit(url)
                    if parsed.scheme or parsed.netloc:
                        continue
                    target = src.parent / unquote(parsed.path) if parsed.path else src
                    siblings.discard(target.resolve())
                    if not target.is_file():
                        errors.append(f'{src.relative_to(stage)} -> {url}')
                    elif parsed.fragment and target.suffix == '.md':
                        if unquote(parsed.fragment) not in parse(target)[1]:
                            errors.append(f'{src.relative_to(stage)} -> {url} (anchor)')
                    count += 1
                if siblings:
                    errors.append(f'{src.relative_to(stage)}: {len(siblings)} missing language links')
        if errors:
            raise SystemExit('\n'.join(errors))
        print(f'{count} offline document and image links verified')


if __name__ == '__main__':
    main()
